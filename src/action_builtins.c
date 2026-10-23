/*
 * action_builtins.c
 *
 * Copyright (C) 2021-2025 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSentry is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "wolfsentry_internal.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_ACTION_BUILTINS_C

/* the public insert wrappers zero action_results before the route table sees
 * them, so the CONNECT that spawns a tracking route is counted here instead,
 * on exactly the route that was just inserted.  caller must hold the lock.
 */
static wolfsentry_errcode_t wolfsentry_builtin_track_peer_count_connect(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_ent_id_t route_id,
    const struct wolfsentry_eventconfig_internal *config)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_route *route = NULL;
    uint16_t new_count;

    ret = wolfsentry_table_ent_get_by_id(WOLFSENTRY_CONTEXT_ARGS_OUT, route_id, (struct wolfsentry_table_ent_header **)&route);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (route->header.parent_table == NULL)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if (route->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ROUTE)
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);

    if (WOLFSENTRY_CHECK_BITS(WOLFSENTRY_ATOMIC_LOAD(route->flags), WOLFSENTRY_ROUTE_FLAG_DONT_COUNT_CURRENT_CONNECTIONS))
        WOLFSENTRY_RETURN_OK;

    /* dispatch counts connections only under a limit, so match it: an unlimited route must stay at zero. */
    if (config->config.max_connection_count == 0)
        WOLFSENTRY_RETURN_OK;

    if (WOLFSENTRY_ATOMIC_LOAD(route->meta.connection_count) >= config->config.max_connection_count)
        WOLFSENTRY_ERROR_RETURN(INCOMPATIBLE_STATE);

    WOLFSENTRY_ATOMIC_INCREMENT_UNSIGNED_SAFELY_BY_ONE(route->meta.connection_count, new_count);
    if (new_count == 0)
        WOLFSENTRY_ERROR_RETURN(OVERFLOW_AVERTED);

    WOLFSENTRY_RETURN_OK;
}

/* this simple action creates a new tracking rule, either as a fallthrough or as
 * a side effect.  it can be used to open a pinhole route for bidirectional
 * traffic, or to track derogatory events on a locally bound port (e.g. crypto
 * negotiation spamming, authentication brute forcing, or connection bombing),
 * or (with network stack integration) to track and block port scanners.
 */
static wolfsentry_errcode_t wolfsentry_builtin_action_track_peer(
    WOLFSENTRY_CONTEXT_ARGS_IN,
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
    wolfsentry_route_flags_t rule_flags;
    const struct wolfsentry_event *rule_parent_event = NULL, *rule_aux_event = NULL;
    const struct wolfsentry_event *ephemeral_parent_event = NULL;
    const struct wolfsentry_eventconfig_internal *ephemeral_config;
    wolfsentry_addr_bits_t rule_local_addr_len, rule_remote_addr_len;
    struct wolfsentry_route_exports target_exports;
    wolfsentry_errcode_t ret;
    wolfsentry_action_res_t insert_action_results = WOLFSENTRY_ACTION_RES_NONE;
    wolfsentry_ent_id_t new_route_id = WOLFSENTRY_ENT_ID_NONE;

    (void)action;
    (void)handler_arg;
    (void)caller_arg;
    (void)route_table;
    (void)trigger_event;
    (void)action_type;

    ret = wolfsentry_route_get_flags(rule_route, &rule_flags);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_route_get_addrs(target_route,
                                     &target_exports.sa_family,
                                     &target_exports.local.addr_len,
                                     &target_exports.local_address,
                                     &target_exports.remote.addr_len,
                                     &target_exports.remote_address);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    ret = wolfsentry_route_get_addrs(rule_route,
                                     NULL,
                                     &rule_local_addr_len,
                                     NULL,
                                     &rule_remote_addr_len,
                                     NULL);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    /* export the target, and set it up for insertion as a new rule by switching
     * its parent event to the rule_route's aux_event.
     *
     * the dynamics for shifting the event from the generator rule to the
     * ephemeral one are handled by the wolfSentry core -- in particular,
     * setting and clearing of route and action_res flags per the event config,
     * and accounting around connection_count, derogatory_count, and
     * commendable_count.
     */

    ret = wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, target_route, &target_exports);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    /* if the target route is already in the route table (as it always is with
     * wolfsentry_route_event_dispatch_by_route() and
     * wolfsentry_route_event_dispatch_by_id()), return early without doing
     * anything.
     */
    if (target_exports.flags & (WOLFSENTRY_ROUTE_FLAG_IN_TABLE | WOLFSENTRY_ROUTE_FLAG_PENDING_DELETE))
        WOLFSENTRY_RETURN_OK;

    rule_parent_event = wolfsentry_route_parent_event(rule_route);
    if (rule_parent_event)
        rule_aux_event = wolfsentry_event_get_aux_event(rule_parent_event);
    if (rule_aux_event)
        ephemeral_parent_event = rule_aux_event;
    else
        ephemeral_parent_event = rule_parent_event;

    if (ephemeral_parent_event != NULL) {
        target_exports.parent_event_label = wolfsentry_event_get_label(ephemeral_parent_event);
        target_exports.parent_event_label_len = WOLFSENTRY_LENGTH_NULL_TERMINATED;
    } else {
        target_exports.parent_event_label = NULL;
        target_exports.parent_event_label_len = 0;
    }

    if ((ephemeral_parent_event != NULL) && (ephemeral_parent_event->config != NULL))
        ephemeral_config = ephemeral_parent_event->config;
    else
        ephemeral_config = &wolfsentry->config;

    /* an ephemeral route with no purge time escapes both the idle purge and
     * max_purgeable_routes, letting a remote peer grow the table without bound.
     * skip the insert but return OK so the rest of the match chain still runs.
     */
    if (ephemeral_config->config.route_idle_time_for_purge <= 0)
        WOLFSENTRY_RETURN_OK;

    target_exports.private_data = NULL;
    target_exports.private_data_size = 0;

    ret = wolfsentry_route_reset_metadata_exports(&target_exports);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    /* can't pass action_results directly to _route_insert -- it would get zeroed. */
    ret = wolfsentry_route_insert_by_exports_into_table(
        WOLFSENTRY_CONTEXT_ARGS_OUT,
        route_table,
        NULL /* void *caller_arg*/,
        &target_exports,
        &new_route_id,
        &insert_action_results);
    WOLFSENTRY_WARN_ON_FAILURE(ret);
    /* no route survives a failed insert, so drop INSERTED (it would suppress generator
     * accounting); other bits are the chain's decisions and are NONE on early failure. */
    if (ret < 0) {
        WOLFSENTRY_CLEAR_BITS(insert_action_results, WOLFSENTRY_ACTION_RES_INSERTED);
    } else if (WOLFSENTRY_CHECK_BITS(insert_action_results, WOLFSENTRY_ACTION_RES_INSERTED) &&
               WOLFSENTRY_CHECK_BITS(*action_results, WOLFSENTRY_ACTION_RES_CONNECT))
    {
        WOLFSENTRY_WARN_ON_FAILURE(wolfsentry_builtin_track_peer_count_connect(WOLFSENTRY_CONTEXT_ARGS_OUT, new_route_id, ephemeral_config));
    }
    *action_results |= insert_action_results; /* copying over the bits is crucial to inhibit double-accounting for
                                               * connection_count, derogatory_count, and commendable_count.
                                               */

    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_action_insert_builtins(
    WOLFSENTRY_CONTEXT_ARGS_IN)
{
    #define HOOK_IN_BUILTIN(handler, label)                             \
        WOLFSENTRY_RERETURN_IF_ERROR(                                   \
            wolfsentry_action_insert_1(                                 \
                WOLFSENTRY_CONTEXT_ARGS_OUT,                            \
                WOLFSENTRY_BUILTIN_LABEL_PREFIX label,                  \
                (int)strlen(WOLFSENTRY_BUILTIN_LABEL_PREFIX label),     \
                WOLFSENTRY_ACTION_FLAG_NONE,                            \
                handler,                                                \
                NULL,                                                   \
                NULL))

    HOOK_IN_BUILTIN(wolfsentry_builtin_action_track_peer, "track-peer-v1");
    WOLFSENTRY_RETURN_OK;
}
