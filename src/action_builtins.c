/*
 * action_builtins.c
 *
 * Copyright (C) 2021-2023 wolfSSL Inc.
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
    wolfsentry_addr_bits_t rule_local_addr_len, rule_remote_addr_len;
    struct wolfsentry_route_exports target_exports;
    wolfsentry_errcode_t ret;

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

    /* check if this was a fallthrough, in which case the caller will insert it. */
    if ((! WOLFSENTRY_MASKIN_BITS(rule_flags, WOLFSENTRY_ROUTE_WILDCARD_FLAGS)) &&
        (rule_remote_addr_len == target_exports.remote.addr_len))
    {
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_INSERT);
        WOLFSENTRY_RETURN_OK;
    }

    /* export the target, and set it up for insertion as a new rule by switching
     * its parent event to the rule_route's aux_event.
     *
     * the dynamics for shifting the event from the electric rule to the
     * ephemeral one are handled by the wolfSentry core -- in particular,
     * setting and clearing of route and action_res flags per the event config,
     * and accounting around connection_count, derogatory_count, and
     * commendable_count.
     */

    ret = wolfsentry_route_export(WOLFSENTRY_CONTEXT_ARGS_OUT, target_route, &target_exports);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    rule_parent_event = wolfsentry_route_parent_event(rule_route);
    if (rule_parent_event)
        rule_aux_event = wolfsentry_event_get_aux_event(rule_parent_event);
    if (rule_aux_event) {
        target_exports.parent_event_label = wolfsentry_event_get_label(rule_aux_event);
        target_exports.parent_event_label_len = WOLFSENTRY_LENGTH_NULL_TERMINATED;
    } else if (rule_parent_event) {
        target_exports.parent_event_label = wolfsentry_event_get_label(rule_parent_event);
        target_exports.parent_event_label_len = WOLFSENTRY_LENGTH_NULL_TERMINATED;
    } else {
        target_exports.parent_event_label = NULL;
        target_exports.parent_event_label_len = 0;
    }

    ret = wolfsentry_route_reset_metadata_exports(&target_exports);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);

    WOLFSENTRY_WARN_ON_FAILURE(
        ret = wolfsentry_route_insert_by_exports_into_table(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            route_table,
            NULL /* void *caller_arg*/,
            &target_exports,
            NULL /* id */,
            action_results));

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
