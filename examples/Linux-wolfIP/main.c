#define _GNU_SOURCE
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_USER_BASE

#include <wolfsentry/wolfsentry.h>
#include <wolfsentry/wolfsentry_json.h>
#include <wolfsentry/wolfsentry_wolfip.h>

#include "wolfip/config.h"

#include <wolfip.h>
#include <wolfip-filter.h>

extern int tap_init(struct wolfIP_ll_dev *dev, const char *name, uint32_t host_ip);

static const char *const CONFIG_PATH = "wolfip-config.json";
static volatile sig_atomic_t stop_flag = 0;

static struct wolfsentry_context *sentry = NULL;
static pid_t ping_pid = -1;

struct icmp_filter_state {
    unsigned long counter;
};

static struct icmp_filter_state icmp_state;

static void on_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static const char *reason_to_string(enum wolfIP_filter_reason reason)
{
    switch (reason) {
    case WOLFIP_FILT_BINDING: return "BINDING";
    case WOLFIP_FILT_DISSOCIATE: return "DISSOCIATE";
    case WOLFIP_FILT_LISTENING: return "LISTENING";
    case WOLFIP_FILT_STOP_LISTENING: return "STOP_LISTENING";
    case WOLFIP_FILT_CONNECTING: return "CONNECTING";
    case WOLFIP_FILT_ACCEPTING: return "ACCEPTING";
    case WOLFIP_FILT_CLOSED: return "CLOSED";
    case WOLFIP_FILT_REMOTE_RESET: return "REMOTE_RESET";
    case WOLFIP_FILT_RECEIVING: return "RECEIVING";
    case WOLFIP_FILT_SENDING: return "SENDING";
    case WOLFIP_FILT_ADDR_UNREACHABLE: return "ADDR_UNREACHABLE";
    case WOLFIP_FILT_PORT_UNREACHABLE: return "PORT_UNREACHABLE";
    case WOLFIP_FILT_INBOUND_ERR: return "INBOUND_ERR";
    case WOLFIP_FILT_OUTBOUND_ERR: return "OUTBOUND_ERR";
    case WOLFIP_FILT_CLOSE_WAIT: return "CLOSE_WAIT";
    default: return "UNKNOWN";
    }
}

static const char *proto_to_name(uint16_t proto)
{
    switch (proto) {
    case WOLFIP_FILTER_PROTO_ETH: return "ETH";
    case WOLFIP_FILTER_PROTO_IP: return "IP";
    case WOLFIP_FILTER_PROTO_TCP: return "TCP";
    case WOLFIP_FILTER_PROTO_UDP: return "UDP";
    case WOLFIP_FILTER_PROTO_ICMP: return "ICMP";
    default: return "UNKNOWN";
    }
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ip_to_str(uint32_t net_ip, char *buf, size_t len)
{
    ip4 host_ip = ee32(net_ip);
    iptoa(host_ip, buf);
    buf[len - 1] = '\0';
}

static void log_event(const struct wolfIP_filter_event *event, const char *tag)
{
    char src_mac[18], dst_mac[18], src_ip[16], dst_ip[16];
    mac_to_str(event->meta.src_mac, src_mac, sizeof(src_mac));
    mac_to_str(event->meta.dst_mac, dst_mac, sizeof(dst_mac));
    ip_to_str(event->meta.src_ip, src_ip, sizeof(src_ip));
    ip_to_str(event->meta.dst_ip, dst_ip, sizeof(dst_ip));

    printf("[%s] proto=%s reason=%s if=%u len=%u %s->%s %s->%s\n",
           tag,
           proto_to_name(event->meta.ip_proto),
           reason_to_string(event->reason),
           event->if_idx,
           event->length,
           src_ip,
           dst_ip,
           src_mac,
           dst_mac);
}

static wolfsentry_errcode_t icmp_mod7_action(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_thread_context *thread,
    const struct wolfsentry_action *action,
    void *handler_arg,
    void *caller_arg,
    const struct wolfsentry_event *trigger_event,
    wolfsentry_action_type_t action_type,
    const struct wolfsentry_route *target_route,
    struct wolfsentry_route_table *route_table,
    struct wolfsentry_route *rule_route,
    wolfsentry_action_res_t *action_results)
{
    struct icmp_filter_state *state = (struct icmp_filter_state *)handler_arg;
    const struct wolfIP_filter_event *event = (const struct wolfIP_filter_event *)caller_arg;
    (void)wolfsentry;
    (void)thread;
    (void)action;
    (void)trigger_event;
    (void)action_type;
    (void)target_route;
    (void)route_table;
    (void)rule_route;

    if (!state || !event || (event->meta.ip_proto != WOLFIP_FILTER_PROTO_ICMP))
        return WOLFSENTRY_ERROR_ENCODE(OK);

    state->counter++;
    if ((state->counter % 7) == 0) {
        log_event(event, "drop-icmp-mod7");
        if (action_results)
            *action_results |= WOLFSENTRY_ACTION_RES_REJECT |
                               WOLFSENTRY_ACTION_RES_DEROGATORY;
    }
    return WOLFSENTRY_ERROR_ENCODE(OK);
}

static void stop_ping_process(void)
{
    if (ping_pid > 0) {
        if (kill(ping_pid, SIGTERM) < 0 && errno != ESRCH)
            perror("kill ping");
        while (waitpid(ping_pid, NULL, 0) < 0) {
            if (errno == EINTR)
                continue;
            perror("waitpid ping");
            break;
        }
        ping_pid = -1;
    }
}

static void start_host_ping(void)
{
    if (ping_pid > 0)
        return;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork ping");
        return;
    }
    if (pid == 0) {
        execlp("ping", "ping", "-n", "-i", "0.5", "-c", "100",
               "-I", TAP_IFNAME, WOLFIP_IP, (char *)NULL);
        perror("execlp ping");
        _exit(EXIT_FAILURE);
    }

    ping_pid = pid;
}

static void register_actions(void)
{
    wolfsentry_errcode_t ret;
    wolfsentry_ent_id_t action_id;

    ret = wolfsentry_action_insert(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(sentry, NULL),
        "icmp-mod7",
        WOLFSENTRY_LENGTH_NULL_TERMINATED,
        WOLFSENTRY_ACTION_FLAG_NONE,
        icmp_mod7_action,
        &icmp_state,
        &action_id);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_action_insert(icmp-mod7): "
                WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(EXIT_FAILURE);
    }
}

static void load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen config");
        exit(EXIT_FAILURE);
    }

    struct wolfsentry_json_process_state *jps;
    wolfsentry_errcode_t ret = wolfsentry_config_json_init(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(sentry, NULL),
        WOLFSENTRY_CONFIG_LOAD_FLAG_NONE,
        &jps);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_config_json_init: "
                WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(EXIT_FAILURE);
    }

    char buf[512], err_buf[512];
    while (!feof(f)) {
        size_t n = fread(buf, 1, sizeof buf, f);
        if (n == 0 && ferror(f)) {
            perror("fread config");
            exit(EXIT_FAILURE);
        }
        ret = wolfsentry_config_json_feed(jps, (const unsigned char *)buf, n, err_buf, sizeof err_buf);
        if (ret < 0) {
            fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
            exit(EXIT_FAILURE);
        }
    }
    fclose(f);

    ret = wolfsentry_config_json_fini(&jps, err_buf, sizeof err_buf);
    if (ret < 0) {
        fprintf(stderr, "%.*s\n", (int)sizeof err_buf, err_buf);
        exit(EXIT_FAILURE);
    }
}

static void install_filter_masks(void)
{
    wolfsentry_errcode_t ret;
    uint32_t mask = WOLFIP_FILT_MASK(WOLFIP_FILT_RECEIVING);

    ret = wolfsentry_install_wolfip_filter_ethernet_callback(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(sentry, NULL),
        mask);
    if (ret < 0) {
        fprintf(stderr, "install ethernet callback failed: "
                WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(EXIT_FAILURE);
    }

    ret = wolfsentry_install_wolfip_filter_ip4_callbacks(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(sentry, NULL),
        mask);
    if (ret < 0) {
        fprintf(stderr, "install ip callback failed: "
                WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(EXIT_FAILURE);
    }

    ret = wolfsentry_install_wolfip_filter_icmp_callbacks(
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(sentry, NULL),
        mask);
    if (ret < 0) {
        fprintf(stderr, "install icmp callback failed: "
                WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        exit(EXIT_FAILURE);
    }
}

static struct wolfIP *start_wolfip(void)
{
    struct wolfIP *stack = NULL;
    struct wolfIP_ll_dev *tapdev;
    struct in_addr host_addr;

    wolfIP_init_static(&stack);
    if (!stack) {
        fprintf(stderr, "wolfIP_init_static failed\n");
        exit(EXIT_FAILURE);
    }

    tapdev = wolfIP_getdev(stack);
    if (!tapdev) {
        fprintf(stderr, "wolfIP_getdev failed\n");
        exit(EXIT_FAILURE);
    }

    if (inet_aton(HOST_STACK_IP, &host_addr) == 0) {
        fprintf(stderr, "inet_aton failed for host stack IP\n");
        exit(EXIT_FAILURE);
    }

    if (tap_init(tapdev, TAP_IFNAME, host_addr.s_addr) < 0) {
        perror("tap_init");
        exit(EXIT_FAILURE);
    }

    wolfIP_ipconfig_set(stack,
        atoip4(WOLFIP_IP),
        atoip4(WOLFIP_NETMASK),
        atoip4(HOST_STACK_IP));

    printf("wolfIP ready on %s (wolfIP=%s, host=%s)\n",
           tapdev->ifname,
           WOLFIP_IP,
           HOST_STACK_IP);
    return stack;
}

int main(void)
{
    struct wolfIP *stack;
    struct wolfsentry_eventconfig evconfig = {
        .route_private_data_size = 32,
        .route_private_data_alignment = 16
    };
    wolfsentry_errcode_t ret;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    ret = wolfsentry_init(
        wolfsentry_build_settings,
        WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(NULL /* hpi */, NULL /* thread */),
        &evconfig,
        &sentry);
    if (ret < 0) {
        fprintf(stderr, "wolfsentry_init failed: "
                WOLFSENTRY_ERROR_FMT "\n", WOLFSENTRY_ERROR_FMT_ARGS(ret));
        return EXIT_FAILURE;
    }

    register_actions();
    load_config(CONFIG_PATH);
    install_filter_masks();

    stack = start_wolfip();
    start_host_ping();

    while (!stop_flag) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        uint32_t delay = wolfIP_poll(stack, tv.tv_sec * 1000 + tv.tv_usec / 1000);
        usleep(delay * 1000);
    }

    stop_ping_process();
    wolfsentry_cleanup_wolfip_filter_callbacks(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(sentry, NULL), NULL);
    wolfsentry_shutdown(WOLFSENTRY_CONTEXT_ARGS_OUT_EX4(&sentry, NULL));

    printf("Exiting.\n");
    return 0;
}
