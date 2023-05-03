/*
 * addr_families.c
 *
 * Copyright (C) 2022-2023 wolfSSL Inc.
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

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_ADDR_FAMILIES_C

static int wolfsentry_addr_family_bynumber_key_cmp(struct wolfsentry_addr_family_bynumber *left, struct wolfsentry_addr_family_bynumber *right) {
    WOLFSENTRY_RETURN_VALUE(left->number - right->number);
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
static inline int wolfsentry_addr_family_byname_key_cmp_1(const char *left_label, unsigned const int left_label_len, const char *right_label, unsigned const int right_label_len) {
    int ret;

    if (left_label_len >= right_label_len) {
        ret = memcmp(left_label, right_label, right_label_len);
        if ((ret == 0) && (left_label_len != right_label_len))
            ret = 1;
    } else {
        ret = memcmp(left_label, right_label, left_label_len);
        if (ret == 0)
            ret = -1;
    }

    WOLFSENTRY_RETURN_VALUE(ret);
}

static int wolfsentry_addr_family_byname_key_cmp(struct wolfsentry_addr_family_byname *left, struct wolfsentry_addr_family_byname *right) {
    return wolfsentry_addr_family_byname_key_cmp_1(left->name, left->name_len, right->name, right->name_len);
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_table_pair(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    struct wolfsentry_addr_family_byname_table *byname_table)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    if (bynumber_table->header.n_ents != 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (byname_table->header.n_ents != 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    bynumber_table->byname_table = byname_table;
    byname_table->bynumber_table = bynumber_table;
    WOLFSENTRY_RETURN_OK;
}
#endif /* WOLFSENTRY_PROTOCOL_NAMES */

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_insert(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    wolfsentry_addr_family_t family_bynumber,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_addr_family_parser_t parser,
    wolfsentry_addr_family_formatter_t formatter,
    int max_addr_bits)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *bynumber = NULL;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    struct wolfsentry_addr_family_byname *byname = NULL;
    size_t byname_size;
#else
    (void)family_byname;
    (void)family_byname_len;
#endif

    if (bynumber_table == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (family_bynumber == WOLFSENTRY_AF_UNSPEC)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((parser == NULL) || (formatter == NULL))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if ((max_addr_bits <= 0) || (max_addr_bits > WOLFSENTRY_MAX_ADDR_BITS))
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if (family_byname == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (family_byname_len < 0)
        family_byname_len = (int)strlen(family_byname);
    if (family_byname_len == 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (family_byname_len > WOLFSENTRY_MAX_LABEL_BYTES) {
        ret = WOLFSENTRY_ERROR_ENCODE(STRING_ARG_TOO_LONG);
        goto out;
    }
#endif

    if ((bynumber = (struct wolfsentry_addr_family_bynumber *)WOLFSENTRY_MALLOC(sizeof *bynumber)) == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto out;
    }

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    byname_size = sizeof *byname + (size_t)family_byname_len + 1;
    if ((byname = (struct wolfsentry_addr_family_byname *)WOLFSENTRY_MALLOC(byname_size)) == NULL) {
        ret = WOLFSENTRY_ERROR_ENCODE(SYS_RESOURCE_FAILED);
        goto out;
    }
#endif

    memset(bynumber, 0, sizeof *bynumber);
    bynumber->number = family_bynumber;
    bynumber->parser = parser;
    bynumber->formatter = formatter;
    bynumber->max_addr_bits = max_addr_bits;
    bynumber->header.refcount = 1;

#ifdef WOLFSENTRY_PROTOCOL_NAMES
    bynumber->byname_ent = byname;

    memset(byname, 0, byname_size);
    byname->bynumber_ent = bynumber;
    memcpy(byname->name, family_byname, (size_t)family_byname_len);
    byname->name_len = (byte)family_byname_len;
    byname->header.refcount = 1;
#endif

    ret = WOLFSENTRY_MUTEX_EX(wolfsentry);
    if (ret < 0)
        goto out;

    if ((ret = wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_OUT, &bynumber->header)) < 0)
        goto out;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_id_allocate(WOLFSENTRY_CONTEXT_ARGS_OUT, &byname->header)) < 0)
        goto out;
#endif

    if ((ret = wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, &bynumber->header, &bynumber_table->header, 1 /* unique_p */)) < 0)
        goto out;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_table_ent_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, &byname->header, &bynumber_table->byname_table->header, 1 /* unique_p */)) < 0) {
        (void)wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &bynumber->header);
        goto out;
    }
#endif

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0) {
        if (bynumber != NULL) {
            if (bynumber->header.id != WOLFSENTRY_ENT_ID_NONE)
                (void)wolfsentry_table_ent_delete_by_id_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &bynumber->header);
            WOLFSENTRY_FREE(bynumber);
        }
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        if (byname != NULL) {
            if (byname->header.id != WOLFSENTRY_ENT_ID_NONE)
                (void)wolfsentry_table_ent_delete_by_id_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &byname->header);
            WOLFSENTRY_FREE(byname);
        }
#endif
    }

    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

static wolfsentry_errcode_t wolfsentry_addr_family_get_bynumber_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    wolfsentry_addr_family_t family_bynumber,
    struct wolfsentry_addr_family_bynumber **addr_family)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber target;
    struct wolfsentry_addr_family_bynumber *addr_family_1 = &target;

    if (bynumber_table == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (bynumber_table->header.ent_type != WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (addr_family == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    target.number = family_bynumber;

    if ((ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &bynumber_table->header, (struct wolfsentry_table_ent_header **)&addr_family_1)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    *addr_family = addr_family_1;

    WOLFSENTRY_RETURN_OK;
}


WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_get_parser(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_family_parser_t *parser)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *addr_family;

    if (parser == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_SHARED_OR_RETURN();
    if ((ret = wolfsentry_addr_family_get_bynumber_1(
             WOLFSENTRY_CONTEXT_ARGS_OUT,
             wolfsentry->addr_families_bynumber,
             family,
             &addr_family)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    *parser = addr_family->parser;
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_get_formatter(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_family_formatter_t *formatter)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *addr_family;

    if (formatter == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    WOLFSENTRY_SHARED_OR_RETURN();
    if ((ret = wolfsentry_addr_family_get_bynumber_1(
             WOLFSENTRY_CONTEXT_ARGS_OUT,
             wolfsentry->addr_families_bynumber,
             family,
             &addr_family)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    *formatter = addr_family->formatter;
    WOLFSENTRY_UNLOCK_AND_RETURN_OK;
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
static wolfsentry_errcode_t wolfsentry_addr_family_get_byname_1(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_byname_table *byname_table,
    const char *family_byname,
    int family_byname_len,
    struct wolfsentry_addr_family_bynumber **addr_family)
{
    wolfsentry_errcode_t ret;
    struct {
        struct wolfsentry_addr_family_byname target;
        byte buf[WOLFSENTRY_MAX_LABEL_BYTES];
    } target;

    struct wolfsentry_addr_family_byname *addr_family_1 = &target.target;

    if (byname_table == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (byname_table->header.ent_type != WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (addr_family == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    *addr_family = NULL;

    if (family_byname == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (family_byname_len < 0)
        family_byname_len = (int)strlen(family_byname);
    if (family_byname_len == 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (family_byname_len > WOLFSENTRY_MAX_LABEL_BYTES)
        WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);

    memcpy(target.target.name, family_byname, (size_t)family_byname_len);
    target.target.name_len = (byte)family_byname_len;

    if ((ret = wolfsentry_table_ent_get(WOLFSENTRY_CONTEXT_ARGS_OUT, &byname_table->header, (struct wolfsentry_table_ent_header **)&addr_family_1)) < 0)
        WOLFSENTRY_ERROR_RERETURN(ret);

    *addr_family = addr_family_1->bynumber_ent;

    WOLFSENTRY_RETURN_OK;
}
#endif


#ifdef WOLFSENTRY_PROTOCOL_NAMES

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent1,
    struct wolfsentry_table_ent_header **new_ent2,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_addr_family_bynumber * const src_bynumber = (struct wolfsentry_addr_family_bynumber * const)src_ent;
    struct wolfsentry_addr_family_bynumber ** const new_bynumber = (struct wolfsentry_addr_family_bynumber ** const)new_ent1;
    struct wolfsentry_addr_family_byname ** const new_byname = (struct wolfsentry_addr_family_byname ** const)new_ent2;
    size_t byname_size = sizeof **new_byname + (size_t)src_bynumber->byname_ent->name_len + 1;

    (void)wolfsentry;
    (void)flags;

    if ((*new_bynumber = (struct wolfsentry_addr_family_bynumber *)WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, sizeof **new_bynumber)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((*new_byname = (struct wolfsentry_addr_family_byname *)WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, byname_size)) == NULL) {
        (void)WOLFSENTRY_FREE_1(dest_context->hpi.allocator, new_byname);
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    }
    memcpy(*new_bynumber, src_bynumber, sizeof **new_bynumber);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent1);
    (*new_bynumber)->byname_ent = *new_byname;
    memcpy(*new_byname, src_bynumber->byname_ent, byname_size);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET(**new_ent2);
    (*new_byname)->bynumber_ent = *new_bynumber;

    WOLFSENTRY_RETURN_OK;
}

#else

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_bynumber_clone(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_addr_family_bynumber * const src_bynumber = (struct wolfsentry_addr_family_bynumber * const)src_ent;
    struct wolfsentry_addr_family_bynumber ** const new_bynumber = (struct wolfsentry_addr_family_bynumber ** const)new_ent;

    (void)wolfsentry;
    (void)flags;

    if ((*new_bynumber = (struct wolfsentry_addr_family_bynumber *)WOLFSENTRY_MALLOC_1(dest_context->hpi.allocator, sizeof **new_bynumber)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_bynumber, src_bynumber, sizeof **new_bynumber);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET((*new_bynumber)->header);

    WOLFSENTRY_RETURN_OK;
}

#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_drop_reference(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber *family_bynumber,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    wolfsentry_refcount_t refs_left;
    if (family_bynumber->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((family_bynumber->header.parent_table != NULL) &&
        (family_bynumber->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    if (action_results != NULL)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    WOLFSENTRY_REFCOUNT_DECREMENT(family_bynumber->header.refcount, refs_left, ret);
    WOLFSENTRY_RERETURN_IF_ERROR(ret);
    if (refs_left > 0)
        WOLFSENTRY_RETURN_OK;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    /* note byname_ent->header.refcount is not used. */
    WOLFSENTRY_FREE(family_bynumber->byname_ent);
#endif
    WOLFSENTRY_FREE(family_bynumber);
    if (action_results)
        WOLFSENTRY_SET_BITS(*action_results, WOLFSENTRY_ACTION_RES_DEALLOCATED);
    WOLFSENTRY_RETURN_OK;
}


static wolfsentry_errcode_t wolfsentry_addr_family_handler_delete_bynumber(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    wolfsentry_addr_family_t family_bynumber,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *old;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_addr_family_get_bynumber_1(WOLFSENTRY_CONTEXT_ARGS_OUT, bynumber_table, family_bynumber, &old)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);

    if ((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->header)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->byname_ent->header)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
#endif

    ret = wolfsentry_addr_family_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, old, action_results);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
static wolfsentry_errcode_t wolfsentry_addr_family_handler_delete_byname(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_addr_family_byname_table *byname_table,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *old;

    WOLFSENTRY_MUTEX_OR_RETURN();

    if ((ret = wolfsentry_addr_family_get_byname_1(WOLFSENTRY_CONTEXT_ARGS_OUT, byname_table, family_byname, family_byname_len, &old)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);

    if ((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->header)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
    if ((ret = wolfsentry_table_ent_delete_1(WOLFSENTRY_CONTEXT_ARGS_OUT, &old->byname_ent->header)) < 0)
        WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);

    ret = wolfsentry_addr_family_drop_reference(WOLFSENTRY_CONTEXT_ARGS_OUT, old, action_results);
    WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
}
#endif

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_handler_install(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family_bynumber,
    const char *family_byname, /* if defined(WOLFSENTRY_PROTOCOL_NAMES), must not NULL, else ignored. */
    int family_byname_len,
    wolfsentry_addr_family_parser_t parser,
    wolfsentry_addr_family_formatter_t formatter,
    int max_addr_bits)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_addr_family_insert(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->addr_families_bynumber, family_bynumber, family_byname, family_byname_len, parser, formatter, max_addr_bits));
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_handler_remove_bynumber(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family_bynumber,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_addr_family_handler_delete_bynumber(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->addr_families_bynumber, family_bynumber, action_results));
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_handler_remove_byname(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_action_res_t *action_results)
{
    WOLFSENTRY_ERROR_RERETURN(wolfsentry_addr_family_handler_delete_byname(WOLFSENTRY_CONTEXT_ARGS_OUT, wolfsentry->addr_families_byname, family_byname, family_byname_len, action_results));
}
#endif

#ifdef WOLFSENTRY_PROTOCOL_NAMES

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_pton(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    const char *family_name,
    int family_name_len,
    wolfsentry_addr_family_t *family_number)
{
    wolfsentry_errcode_t ret;

    if (family_name == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (family_number == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (family_name_len < 0)
        family_name_len = (int)strlen(family_name);

    /* don't incur the expense of coherent table access if the table is empty at
     * call time.
     */
    if (WOLFSENTRY_ATOMIC_LOAD(wolfsentry->addr_families_byname->header.n_ents) > 0) {
        struct wolfsentry_addr_family_bynumber *addr_family;
        WOLFSENTRY_SHARED_OR_RETURN();
        ret = wolfsentry_addr_family_get_byname_1(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            wolfsentry->addr_families_byname,
            family_name,
            (int)family_name_len,
            &addr_family);
        WOLFSENTRY_UNLOCK_FOR_RETURN();
        if (ret >= 0) {
            *family_number = addr_family->number;
            WOLFSENTRY_RETURN_OK;
        } else if (! WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
            WOLFSENTRY_ERROR_RERETURN(ret);
    }

    if (strcaseeq(family_name, "UNIX", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_UNIX; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "LOCAL", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_LOCAL; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "INET", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_INET; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "AX25", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_AX25; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IPX", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IPX; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "APPLETALK", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_APPLETALK; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "NETROM", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_NETROM; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "BRIDGE", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_BRIDGE; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ATMPVC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ATMPVC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "X25", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_X25; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "INET6", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_INET6; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ROSE", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ROSE; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "DECnet", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_DECnet; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "NETBEUI", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_NETBEUI; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "SECURITY", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_SECURITY; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "KEY", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_KEY; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "NETLINK", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_NETLINK; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ROUTE", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ROUTE; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "PACKET", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_PACKET; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ASH", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ASH; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ECONET", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ECONET; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ATMSVC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ATMSVC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "RDS", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_RDS; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "SNA", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_SNA; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IRDA", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IRDA; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "PPPOX", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_PPPOX; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "WANPIPE", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_WANPIPE; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "LLC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_LLC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IB", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IB; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "MPLS", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_MPLS; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "CAN", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_CAN; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "TIPC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_TIPC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "BLUETOOTH", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_BLUETOOTH; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IUCV", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IUCV; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "RXRPC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_RXRPC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ISDN", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ISDN; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "PHONET", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_PHONET; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IEEE802154", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IEEE802154; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "CAIF", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_CAIF; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ALG", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ALG; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "NFC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_NFC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "VSOCK", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_VSOCK; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "KCM", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_KCM; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "QIPCRTR", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_QIPCRTR; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "SMC", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_SMC; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "XDP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_XDP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IMPLINK", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IMPLINK; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "PUP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_PUP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "CHAOS", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_CHAOS; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "NETBIOS", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_NETBIOS; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ISO", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ISO; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "OSI", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_OSI; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ECMA", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ECMA; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "DATAKIT", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_DATAKIT; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "DLI", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_DLI; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "LAT", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_LAT; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "HYLINK", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_HYLINK; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "LINK", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_LINK; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "COIP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_COIP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "CNT", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_CNT; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "SIP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_SIP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "SLOW", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_SLOW; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "SCLUSTER", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_SCLUSTER; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "ARP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_ARP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "IEEE80211", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_IEEE80211; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "INET_SDP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_INET_SDP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "INET6_SDP", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_INET6_SDP; WOLFSENTRY_RETURN_OK; }
    if (strcaseeq(family_name, "HYPERV", (size_t)family_name_len))
        { *family_number = WOLFSENTRY_AF_HYPERV; WOLFSENTRY_RETURN_OK; }

    WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
}

static wolfsentry_errcode_t wolfsentry_addr_family_ntop_1(
    wolfsentry_addr_family_t family,
    const char **family_name)
{
    switch(family) {
    case WOLFSENTRY_AF_UNSPEC:
        { *family_name = "UNSPEC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_LOCAL: /* AF_UNIX is an alias. */
        { *family_name = "LOCAL"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_INET:
        { *family_name = "INET"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_AX25:
        { *family_name = "AX25"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IPX:
        { *family_name = "IPX"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_APPLETALK:
        { *family_name = "APPLETALK"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_NETROM:
        { *family_name = "NETROM"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_BRIDGE:
        { *family_name = "BRIDGE"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ATMPVC:
        { *family_name = "ATMPVC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_X25:
        { *family_name = "X25"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_INET6:
        { *family_name = "INET6"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ROSE:
        { *family_name = "ROSE"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_DECnet:
        { *family_name = "DECnet"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_NETBEUI:
        { *family_name = "NETBEUI"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_SECURITY:
        { *family_name = "SECURITY"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_KEY:
        { *family_name = "KEY"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ROUTE: /* AF_NETLINK is an alias. */
        { *family_name = "ROUTE"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_PACKET:
        { *family_name = "PACKET"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ASH:
        { *family_name = "ASH"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ECONET:
        { *family_name = "ECONET"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ATMSVC:
        { *family_name = "ATMSVC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_RDS:
        { *family_name = "RDS"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_SNA:
        { *family_name = "SNA"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IRDA:
        { *family_name = "IRDA"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_PPPOX:
        { *family_name = "PPPOX"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_WANPIPE:
        { *family_name = "WANPIPE"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_LLC:
        { *family_name = "LLC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IB:
        { *family_name = "IB"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_MPLS:
        { *family_name = "MPLS"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_CAN:
        { *family_name = "CAN"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_TIPC:
        { *family_name = "TIPC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_BLUETOOTH:
        { *family_name = "BLUETOOTH"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IUCV:
        { *family_name = "IUCV"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_RXRPC:
        { *family_name = "RXRPC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ISDN:
        { *family_name = "ISDN"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_PHONET:
        { *family_name = "PHONET"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IEEE802154:
        { *family_name = "IEEE802154"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_CAIF:
        { *family_name = "CAIF"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ALG:
        { *family_name = "ALG"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_NFC:
        { *family_name = "NFC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_VSOCK:
        { *family_name = "VSOCK"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_KCM:
        { *family_name = "KCM"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_QIPCRTR:
        { *family_name = "QIPCRTR"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_SMC:
        { *family_name = "SMC"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_XDP:
        { *family_name = "XDP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IMPLINK:
        { *family_name = "IMPLINK"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_PUP:
        { *family_name = "PUP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_CHAOS:
        { *family_name = "CHAOS"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_NETBIOS:
        { *family_name = "NETBIOS"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ISO: /* AF_OSI is an alias. */
        { *family_name = "ISO"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ECMA:
        { *family_name = "ECMA"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_DATAKIT:
        { *family_name = "DATAKIT"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_DLI:
        { *family_name = "DLI"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_LAT:
        { *family_name = "LAT"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_HYLINK:
        { *family_name = "HYLINK"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_LINK:
        { *family_name = "LINK"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_COIP:
        { *family_name = "COIP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_CNT:
        { *family_name = "CNT"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_SIP:
        { *family_name = "SIP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_SLOW:
        { *family_name = "SLOW"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_SCLUSTER:
        { *family_name = "SCLUSTER"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_ARP:
        { *family_name = "ARP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_IEEE80211:
        { *family_name = "IEEE80211"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_INET_SDP:
        { *family_name = "INET_SDP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_INET6_SDP:
        { *family_name = "INET6_SDP"; WOLFSENTRY_RETURN_OK; }
    case WOLFSENTRY_AF_HYPERV:
        { *family_name = "HYPERV"; WOLFSENTRY_RETURN_OK; }
    default:
        WOLFSENTRY_ERROR_RETURN(ITEM_NOT_FOUND);
    }
}

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_addr_family_ntop(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    wolfsentry_addr_family_t family,
    struct wolfsentry_addr_family_bynumber **addr_family,
    const char **family_name)
{
    wolfsentry_errcode_t ret;

    if (family_name == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if (addr_family != NULL)
        *addr_family = NULL;
    /* don't incur the expense of coherent table access if the table is empty at
     * call time.
     */
    if ((addr_family != NULL) && (WOLFSENTRY_ATOMIC_LOAD(wolfsentry->addr_families_bynumber->header.n_ents) > 0)) {
        WOLFSENTRY_SHARED_OR_RETURN();
        ret = wolfsentry_addr_family_get_bynumber_1(
            WOLFSENTRY_CONTEXT_ARGS_OUT,
            wolfsentry->addr_families_bynumber,
            family,
            addr_family);
        if (ret >= 0) {
            WOLFSENTRY_REFCOUNT_INCREMENT((*addr_family)->header.refcount, ret);
            WOLFSENTRY_UNLOCK_AND_RERETURN_IF_ERROR(ret);
            *family_name = (*addr_family)->byname_ent->name;
            WOLFSENTRY_UNLOCK_AND_RETURN_OK;
        } else if (! WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND))
            WOLFSENTRY_ERROR_UNLOCK_AND_RERETURN(ret);
        WOLFSENTRY_UNLOCK_FOR_RETURN();
    }

    WOLFSENTRY_ERROR_RERETURN(wolfsentry_addr_family_ntop_1(family, family_name));
}

#endif /* WOLFSENTRY_PROTOCOL_NAMES */

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_bynumber_table_init(
    struct wolfsentry_addr_family_bynumber_table *addr_family_bynumber_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(addr_family_bynumber_table->header);
    addr_family_bynumber_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_addr_family_bynumber_key_cmp;
    addr_family_bynumber_table->header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_addr_family_drop_reference;
    addr_family_bynumber_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER;
    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_bynumber_table_clone_header(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)src_table;
    (void)dest_context;
    (void)dest_table;
    (void)flags;

    WOLFSENTRY_RETURN_OK;
}
#endif /* !WOLFSENTRY_PROTOCOL_NAMES */

#ifdef WOLFSENTRY_PROTOCOL_NAMES
WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_byname_table_init(
    struct wolfsentry_addr_family_byname_table *addr_family_byname_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(addr_family_byname_table->header);
    addr_family_byname_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_addr_family_byname_key_cmp;
    addr_family_byname_table->header.free_fn = NULL;
    addr_family_byname_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME;
    WOLFSENTRY_RETURN_OK;
}

WOLFSENTRY_LOCAL wolfsentry_errcode_t wolfsentry_addr_family_table_clone_headers(
    WOLFSENTRY_CONTEXT_ARGS_IN,
    struct wolfsentry_table_header *src_table1,
    struct wolfsentry_table_header *src_table2,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table1,
    struct wolfsentry_table_header *dest_table2,
    wolfsentry_clone_flags_t flags)
{
    WOLFSENTRY_CONTEXT_ARGS_NOT_USED;
    (void)src_table1;
    (void)src_table2;
    (void)dest_context;
    (void)dest_table1;
    (void)dest_table2;
    (void)flags;

    WOLFSENTRY_RETURN_OK;
}
#endif /* WOLFSENTRY_PROTOCOL_NAMES */
