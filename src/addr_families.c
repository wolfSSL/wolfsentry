/*
 * addr_families.c
 *
 * Copyright (C) 2022 wolfSSL Inc.
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
    return left->number - right->number;
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

    return ret;
}

static int wolfsentry_addr_family_byname_key_cmp(struct wolfsentry_addr_family_byname *left, struct wolfsentry_addr_family_byname *right) {
    return wolfsentry_addr_family_byname_key_cmp_1(left->name, left->name_len, right->name, right->name_len);
}

wolfsentry_errcode_t wolfsentry_addr_family_table_pair(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    struct wolfsentry_addr_family_byname_table *byname_table)
{
    (void)wolfsentry;
    if (bynumber_table->header.n_ents != 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    if (byname_table->header.n_ents != 0)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
    bynumber_table->byname_table = byname_table;
    byname_table->bynumber_table = bynumber_table;
    WOLFSENTRY_RETURN_OK;
}
#endif /* WOLFSENTRY_PROTOCOL_NAMES */

wolfsentry_errcode_t wolfsentry_addr_family_insert(
    struct wolfsentry_context *wolfsentry,
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

    if ((ret = wolfsentry_id_allocate(wolfsentry, &bynumber->header)) < 0)
        goto out;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_id_allocate(wolfsentry, &byname->header)) < 0)
        goto out;
#endif

    if ((ret = wolfsentry_table_ent_insert(wolfsentry, &bynumber->header, &bynumber_table->header, 1 /* unique_p */)) < 0)
        goto out;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_table_ent_insert(wolfsentry, &byname->header, &bynumber_table->byname_table->header, 1 /* unique_p */)) < 0) {
        (void)wolfsentry_table_ent_delete_1(wolfsentry, &bynumber->header);
        goto out;
    }
#endif

    ret = WOLFSENTRY_ERROR_ENCODE(OK);

  out:

    if (ret < 0) {
        if (bynumber != NULL) {
            if (bynumber->header.id != WOLFSENTRY_ENT_ID_NONE)
                wolfsentry_table_ent_delete_by_id_1(wolfsentry, &bynumber->header);
            WOLFSENTRY_FREE(bynumber);
        }
#ifdef WOLFSENTRY_PROTOCOL_NAMES
        if (byname != NULL) {
            if (byname->header.id != WOLFSENTRY_ENT_ID_NONE)
                wolfsentry_table_ent_delete_by_id_1(wolfsentry, &byname->header);
            WOLFSENTRY_FREE(byname);
        }
#endif
    }

    return ret;
}

static wolfsentry_errcode_t wolfsentry_addr_family_get_bynumber_1(
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

    if ((ret = wolfsentry_table_ent_get(&bynumber_table->header, (struct wolfsentry_table_ent_header **)&addr_family_1)) < 0)
        return ret;

    *addr_family = addr_family_1;

    WOLFSENTRY_RETURN_OK;
}


wolfsentry_errcode_t wolfsentry_addr_family_get_parser(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_family_parser_t *parser)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *addr_family;

    if (parser == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((ret = wolfsentry_addr_family_get_bynumber_1(
             wolfsentry->addr_families_bynumber,
             family,
             &addr_family)) < 0)
        return ret;
    *parser = addr_family->parser;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_addr_family_get_formatter(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_addr_family_t family,
    wolfsentry_addr_family_formatter_t *formatter)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *addr_family;

    if (formatter == NULL)
        WOLFSENTRY_ERROR_RETURN(INVALID_ARG);

    if ((ret = wolfsentry_addr_family_get_bynumber_1(
             wolfsentry->addr_families_bynumber,
             family,
             &addr_family)) < 0)
        return ret;
    *formatter = addr_family->formatter;
    WOLFSENTRY_RETURN_OK;
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
static wolfsentry_errcode_t wolfsentry_addr_family_get_byname_1(
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

    if ((ret = wolfsentry_table_ent_get(&byname_table->header, (struct wolfsentry_table_ent_header **)&addr_family_1)) < 0)
        return ret;

    *addr_family = addr_family_1->bynumber_ent;

    WOLFSENTRY_RETURN_OK;
}
#endif


#ifdef WOLFSENTRY_PROTOCOL_NAMES

wolfsentry_errcode_t wolfsentry_addr_family_clone(
    struct wolfsentry_context *wolfsentry,
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

    if ((*new_bynumber = dest_context->allocator.malloc(dest_context->allocator.context, sizeof **new_bynumber)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    if ((*new_byname = dest_context->allocator.malloc(dest_context->allocator.context, byname_size)) == NULL) {
        (void)dest_context->allocator.free(dest_context->allocator.context, new_byname);
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

wolfsentry_errcode_t wolfsentry_addr_family_bynumber_clone(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_ent_header *src_ent,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_ent_header **new_ent,
    wolfsentry_clone_flags_t flags)
{
    struct wolfsentry_addr_family_bynumber * const src_bynumber = (struct wolfsentry_addr_family_bynumber * const)src_ent;
    struct wolfsentry_addr_family_bynumber ** const new_bynumber = (struct wolfsentry_addr_family_bynumber ** const)new_ent;

    (void)wolfsentry;
    (void)flags;

    if ((*new_bynumber = dest_context->allocator.malloc(dest_context->allocator.context, sizeof **new_bynumber)) == NULL)
        WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    memcpy(*new_bynumber, src_bynumber, sizeof **new_bynumber);
    WOLFSENTRY_TABLE_ENT_HEADER_RESET((*new_bynumber)->header);

    WOLFSENTRY_RETURN_OK;
}

#endif

wolfsentry_errcode_t wolfsentry_addr_family_drop_reference(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_addr_family_bynumber *family_bynumber,
    wolfsentry_action_res_t *action_results)
{
    if (family_bynumber->header.refcount <= 0)
        WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    if ((family_bynumber->header.parent_table != NULL) &&
        (family_bynumber->header.parent_table->ent_type != WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER))
        WOLFSENTRY_ERROR_RETURN(WRONG_OBJECT);
    if (action_results != NULL)
        WOLFSENTRY_CLEAR_ALL_BITS(*action_results);
    if (WOLFSENTRY_REFCOUNT_DECREMENT(family_bynumber->header.refcount) > 0)
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
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_addr_family_bynumber_table *bynumber_table,
    wolfsentry_addr_family_t family_bynumber,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *old;

    if ((ret = wolfsentry_addr_family_get_bynumber_1(bynumber_table, family_bynumber, &old)) < 0)
        return ret;

    if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, &old->header)) < 0)
        return ret;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, &old->byname_ent->header)) < 0)
        return ret;
#endif

    return wolfsentry_addr_family_drop_reference(wolfsentry, old, action_results);
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
static wolfsentry_errcode_t wolfsentry_addr_family_handler_delete_byname(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_addr_family_byname_table *byname_table,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_action_res_t *action_results)
{
    wolfsentry_errcode_t ret;
    struct wolfsentry_addr_family_bynumber *old;

    if ((ret = wolfsentry_addr_family_get_byname_1(byname_table, family_byname, family_byname_len, &old)) < 0)
        return ret;

    if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, &old->header)) < 0)
        return ret;
#ifdef WOLFSENTRY_PROTOCOL_NAMES
    if ((ret = wolfsentry_table_ent_delete_1(wolfsentry, &old->byname_ent->header)) < 0)
        return ret;
#endif

    return wolfsentry_addr_family_drop_reference(wolfsentry, old, action_results);
}
#endif

wolfsentry_errcode_t wolfsentry_addr_family_handler_install(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_addr_family_t family_bynumber,
    const char *family_byname, /* if defined(WOLFSENTRY_PROTOCOL_NAMES), must not NULL, else ignored. */
    int family_byname_len,
    wolfsentry_addr_family_parser_t parser,
    wolfsentry_addr_family_formatter_t formatter,
    int max_addr_bits)
{
    return wolfsentry_addr_family_insert(wolfsentry, wolfsentry->addr_families_bynumber, family_bynumber, family_byname, family_byname_len, parser, formatter, max_addr_bits);
}

wolfsentry_errcode_t wolfsentry_addr_family_handler_remove_bynumber(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_addr_family_t family_bynumber,
    wolfsentry_action_res_t *action_results)
{
    return wolfsentry_addr_family_handler_delete_bynumber(wolfsentry, wolfsentry->addr_families_bynumber, family_bynumber, action_results);
}

#ifdef WOLFSENTRY_PROTOCOL_NAMES
wolfsentry_errcode_t wolfsentry_addr_family_handler_remove_byname(
    struct wolfsentry_context *wolfsentry,
    const char *family_byname,
    int family_byname_len,
    wolfsentry_action_res_t *action_results)
{
    return wolfsentry_addr_family_handler_delete_byname(wolfsentry, wolfsentry->addr_families_byname, family_byname, family_byname_len, action_results);
}
#endif

#ifdef WOLFSENTRY_PROTOCOL_NAMES

wolfsentry_addr_family_t wolfsentry_addr_family_pton(
    struct wolfsentry_context *wolfsentry,
    const char *family_name,
    int family_name_len,
    wolfsentry_errcode_t *errcode)
{
    wolfsentry_errcode_t ret;

    if (family_name == NULL) {
        if (errcode != NULL)
            *errcode = WOLFSENTRY_ERROR_ENCODE(INVALID_ARG);
        return WOLFSENTRY_AF_UNSPEC;
    }

    if (family_name_len < 0)
        family_name_len = (int)strlen(family_name);

    {
        struct wolfsentry_addr_family_bynumber *addr_family;
        ret = wolfsentry_addr_family_get_byname_1(
            wolfsentry->addr_families_byname,
            family_name,
            (int)family_name_len,
            &addr_family);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            if (errcode)
                *errcode = ret;
            return addr_family->number;
        } else if (! WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND)) {
            if (errcode != NULL)
                *errcode = ret;
            return WOLFSENTRY_AF_UNSPEC;
        }
    }

    if (errcode)
        *errcode = WOLFSENTRY_ERROR_ENCODE(OK);
    if (strcaseeq(family_name, "UNIX", (size_t)family_name_len))
        return WOLFSENTRY_AF_UNIX;
    if (strcaseeq(family_name, "LOCAL", (size_t)family_name_len))
        return WOLFSENTRY_AF_LOCAL;
    if (strcaseeq(family_name, "INET", (size_t)family_name_len))
        return WOLFSENTRY_AF_INET;
    if (strcaseeq(family_name, "AX25", (size_t)family_name_len))
        return WOLFSENTRY_AF_AX25;
    if (strcaseeq(family_name, "IPX", (size_t)family_name_len))
        return WOLFSENTRY_AF_IPX;
    if (strcaseeq(family_name, "APPLETALK", (size_t)family_name_len))
        return WOLFSENTRY_AF_APPLETALK;
    if (strcaseeq(family_name, "NETROM", (size_t)family_name_len))
        return WOLFSENTRY_AF_NETROM;
    if (strcaseeq(family_name, "BRIDGE", (size_t)family_name_len))
        return WOLFSENTRY_AF_BRIDGE;
    if (strcaseeq(family_name, "ATMPVC", (size_t)family_name_len))
        return WOLFSENTRY_AF_ATMPVC;
    if (strcaseeq(family_name, "X25", (size_t)family_name_len))
        return WOLFSENTRY_AF_X25;
    if (strcaseeq(family_name, "INET6", (size_t)family_name_len))
        return WOLFSENTRY_AF_INET6;
    if (strcaseeq(family_name, "ROSE", (size_t)family_name_len))
        return WOLFSENTRY_AF_ROSE;
    if (strcaseeq(family_name, "DECnet", (size_t)family_name_len))
        return WOLFSENTRY_AF_DECnet;
    if (strcaseeq(family_name, "NETBEUI", (size_t)family_name_len))
        return WOLFSENTRY_AF_NETBEUI;
    if (strcaseeq(family_name, "SECURITY", (size_t)family_name_len))
        return WOLFSENTRY_AF_SECURITY;
    if (strcaseeq(family_name, "KEY", (size_t)family_name_len))
        return WOLFSENTRY_AF_KEY;
    if (strcaseeq(family_name, "NETLINK", (size_t)family_name_len))
        return WOLFSENTRY_AF_NETLINK;
    if (strcaseeq(family_name, "ROUTE", (size_t)family_name_len))
        return WOLFSENTRY_AF_ROUTE;
    if (strcaseeq(family_name, "PACKET", (size_t)family_name_len))
        return WOLFSENTRY_AF_PACKET;
    if (strcaseeq(family_name, "ASH", (size_t)family_name_len))
        return WOLFSENTRY_AF_ASH;
    if (strcaseeq(family_name, "ECONET", (size_t)family_name_len))
        return WOLFSENTRY_AF_ECONET;
    if (strcaseeq(family_name, "ATMSVC", (size_t)family_name_len))
        return WOLFSENTRY_AF_ATMSVC;
    if (strcaseeq(family_name, "RDS", (size_t)family_name_len))
        return WOLFSENTRY_AF_RDS;
    if (strcaseeq(family_name, "SNA", (size_t)family_name_len))
        return WOLFSENTRY_AF_SNA;
    if (strcaseeq(family_name, "IRDA", (size_t)family_name_len))
        return WOLFSENTRY_AF_IRDA;
    if (strcaseeq(family_name, "PPPOX", (size_t)family_name_len))
        return WOLFSENTRY_AF_PPPOX;
    if (strcaseeq(family_name, "WANPIPE", (size_t)family_name_len))
        return WOLFSENTRY_AF_WANPIPE;
    if (strcaseeq(family_name, "LLC", (size_t)family_name_len))
        return WOLFSENTRY_AF_LLC;
    if (strcaseeq(family_name, "IB", (size_t)family_name_len))
        return WOLFSENTRY_AF_IB;
    if (strcaseeq(family_name, "MPLS", (size_t)family_name_len))
        return WOLFSENTRY_AF_MPLS;
    if (strcaseeq(family_name, "CAN", (size_t)family_name_len))
        return WOLFSENTRY_AF_CAN;
    if (strcaseeq(family_name, "TIPC", (size_t)family_name_len))
        return WOLFSENTRY_AF_TIPC;
    if (strcaseeq(family_name, "BLUETOOTH", (size_t)family_name_len))
        return WOLFSENTRY_AF_BLUETOOTH;
    if (strcaseeq(family_name, "IUCV", (size_t)family_name_len))
        return WOLFSENTRY_AF_IUCV;
    if (strcaseeq(family_name, "RXRPC", (size_t)family_name_len))
        return WOLFSENTRY_AF_RXRPC;
    if (strcaseeq(family_name, "ISDN", (size_t)family_name_len))
        return WOLFSENTRY_AF_ISDN;
    if (strcaseeq(family_name, "PHONET", (size_t)family_name_len))
        return WOLFSENTRY_AF_PHONET;
    if (strcaseeq(family_name, "IEEE802154", (size_t)family_name_len))
        return WOLFSENTRY_AF_IEEE802154;
    if (strcaseeq(family_name, "CAIF", (size_t)family_name_len))
        return WOLFSENTRY_AF_CAIF;
    if (strcaseeq(family_name, "ALG", (size_t)family_name_len))
        return WOLFSENTRY_AF_ALG;
    if (strcaseeq(family_name, "NFC", (size_t)family_name_len))
        return WOLFSENTRY_AF_NFC;
    if (strcaseeq(family_name, "VSOCK", (size_t)family_name_len))
        return WOLFSENTRY_AF_VSOCK;
    if (strcaseeq(family_name, "KCM", (size_t)family_name_len))
        return WOLFSENTRY_AF_KCM;
    if (strcaseeq(family_name, "QIPCRTR", (size_t)family_name_len))
        return WOLFSENTRY_AF_QIPCRTR;
    if (strcaseeq(family_name, "SMC", (size_t)family_name_len))
        return WOLFSENTRY_AF_SMC;
    if (strcaseeq(family_name, "XDP", (size_t)family_name_len))
        return WOLFSENTRY_AF_XDP;
    if (strcaseeq(family_name, "IMPLINK", (size_t)family_name_len))
        return WOLFSENTRY_AF_IMPLINK;
    if (strcaseeq(family_name, "PUP", (size_t)family_name_len))
        return WOLFSENTRY_AF_PUP;
    if (strcaseeq(family_name, "CHAOS", (size_t)family_name_len))
        return WOLFSENTRY_AF_CHAOS;
    if (strcaseeq(family_name, "NETBIOS", (size_t)family_name_len))
        return WOLFSENTRY_AF_NETBIOS;
    if (strcaseeq(family_name, "ISO", (size_t)family_name_len))
        return WOLFSENTRY_AF_ISO;
    if (strcaseeq(family_name, "OSI", (size_t)family_name_len))
        return WOLFSENTRY_AF_OSI;
    if (strcaseeq(family_name, "ECMA", (size_t)family_name_len))
        return WOLFSENTRY_AF_ECMA;
    if (strcaseeq(family_name, "DATAKIT", (size_t)family_name_len))
        return WOLFSENTRY_AF_DATAKIT;
    if (strcaseeq(family_name, "DLI", (size_t)family_name_len))
        return WOLFSENTRY_AF_DLI;
    if (strcaseeq(family_name, "LAT", (size_t)family_name_len))
        return WOLFSENTRY_AF_LAT;
    if (strcaseeq(family_name, "HYLINK", (size_t)family_name_len))
        return WOLFSENTRY_AF_HYLINK;
    if (strcaseeq(family_name, "LINK", (size_t)family_name_len))
        return WOLFSENTRY_AF_LINK;
    if (strcaseeq(family_name, "COIP", (size_t)family_name_len))
        return WOLFSENTRY_AF_COIP;
    if (strcaseeq(family_name, "CNT", (size_t)family_name_len))
        return WOLFSENTRY_AF_CNT;
    if (strcaseeq(family_name, "SIP", (size_t)family_name_len))
        return WOLFSENTRY_AF_SIP;
    if (strcaseeq(family_name, "SLOW", (size_t)family_name_len))
        return WOLFSENTRY_AF_SLOW;
    if (strcaseeq(family_name, "SCLUSTER", (size_t)family_name_len))
        return WOLFSENTRY_AF_SCLUSTER;
    if (strcaseeq(family_name, "ARP", (size_t)family_name_len))
        return WOLFSENTRY_AF_ARP;
    if (strcaseeq(family_name, "IEEE80211", (size_t)family_name_len))
        return WOLFSENTRY_AF_IEEE80211;
    if (strcaseeq(family_name, "INET_SDP", (size_t)family_name_len))
        return WOLFSENTRY_AF_INET_SDP;
    if (strcaseeq(family_name, "INET6_SDP", (size_t)family_name_len))
        return WOLFSENTRY_AF_INET6_SDP;
    if (strcaseeq(family_name, "HYPERV", (size_t)family_name_len))
        return WOLFSENTRY_AF_HYPERV;

    if (errcode != NULL)
        *errcode = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
    return WOLFSENTRY_AF_UNSPEC;
}

static const char *wolfsentry_addr_family_ntop_1(
    wolfsentry_addr_family_t family,
    wolfsentry_errcode_t *errcode)
{
    if (errcode != NULL)
        *errcode = WOLFSENTRY_ERROR_ENCODE(OK);
    switch(family) {
    case WOLFSENTRY_AF_UNSPEC:
        return "UNSPEC";
    case WOLFSENTRY_AF_LOCAL: /* AF_UNIX is an alias. */
        return "LOCAL";
    case WOLFSENTRY_AF_INET:
        return "INET";
    case WOLFSENTRY_AF_AX25:
        return "AX25";
    case WOLFSENTRY_AF_IPX:
        return "IPX";
    case WOLFSENTRY_AF_APPLETALK:
        return "APPLETALK";
    case WOLFSENTRY_AF_NETROM:
        return "NETROM";
    case WOLFSENTRY_AF_BRIDGE:
        return "BRIDGE";
    case WOLFSENTRY_AF_ATMPVC:
        return "ATMPVC";
    case WOLFSENTRY_AF_X25:
        return "X25";
    case WOLFSENTRY_AF_INET6:
        return "INET6";
    case WOLFSENTRY_AF_ROSE:
        return "ROSE";
    case WOLFSENTRY_AF_DECnet:
        return "DECnet";
    case WOLFSENTRY_AF_NETBEUI:
        return "NETBEUI";
    case WOLFSENTRY_AF_SECURITY:
        return "SECURITY";
    case WOLFSENTRY_AF_KEY:
        return "KEY";
    case WOLFSENTRY_AF_ROUTE: /* AF_NETLINK is an alias. */
        return "ROUTE";
    case WOLFSENTRY_AF_PACKET:
        return "PACKET";
    case WOLFSENTRY_AF_ASH:
        return "ASH";
    case WOLFSENTRY_AF_ECONET:
        return "ECONET";
    case WOLFSENTRY_AF_ATMSVC:
        return "ATMSVC";
    case WOLFSENTRY_AF_RDS:
        return "RDS";
    case WOLFSENTRY_AF_SNA:
        return "SNA";
    case WOLFSENTRY_AF_IRDA:
        return "IRDA";
    case WOLFSENTRY_AF_PPPOX:
        return "PPPOX";
    case WOLFSENTRY_AF_WANPIPE:
        return "WANPIPE";
    case WOLFSENTRY_AF_LLC:
        return "LLC";
    case WOLFSENTRY_AF_IB:
        return "IB";
    case WOLFSENTRY_AF_MPLS:
        return "MPLS";
    case WOLFSENTRY_AF_CAN:
        return "CAN";
    case WOLFSENTRY_AF_TIPC:
        return "TIPC";
    case WOLFSENTRY_AF_BLUETOOTH:
        return "BLUETOOTH";
    case WOLFSENTRY_AF_IUCV:
        return "IUCV";
    case WOLFSENTRY_AF_RXRPC:
        return "RXRPC";
    case WOLFSENTRY_AF_ISDN:
        return "ISDN";
    case WOLFSENTRY_AF_PHONET:
        return "PHONET";
    case WOLFSENTRY_AF_IEEE802154:
        return "IEEE802154";
    case WOLFSENTRY_AF_CAIF:
        return "CAIF";
    case WOLFSENTRY_AF_ALG:
        return "ALG";
    case WOLFSENTRY_AF_NFC:
        return "NFC";
    case WOLFSENTRY_AF_VSOCK:
        return "VSOCK";
    case WOLFSENTRY_AF_KCM:
        return "KCM";
    case WOLFSENTRY_AF_QIPCRTR:
        return "QIPCRTR";
    case WOLFSENTRY_AF_SMC:
        return "SMC";
    case WOLFSENTRY_AF_XDP:
        return "XDP";
    case WOLFSENTRY_AF_IMPLINK:
        return "IMPLINK";
    case WOLFSENTRY_AF_PUP:
        return "PUP";
    case WOLFSENTRY_AF_CHAOS:
        return "CHAOS";
    case WOLFSENTRY_AF_NETBIOS:
        return "NETBIOS";
    case WOLFSENTRY_AF_ISO: /* AF_OSI is an alias. */
        return "ISO";
    case WOLFSENTRY_AF_ECMA:
        return "ECMA";
    case WOLFSENTRY_AF_DATAKIT:
        return "DATAKIT";
    case WOLFSENTRY_AF_DLI:
        return "DLI";
    case WOLFSENTRY_AF_LAT:
        return "LAT";
    case WOLFSENTRY_AF_HYLINK:
        return "HYLINK";
    case WOLFSENTRY_AF_LINK:
        return "LINK";
    case WOLFSENTRY_AF_COIP:
        return "COIP";
    case WOLFSENTRY_AF_CNT:
        return "CNT";
    case WOLFSENTRY_AF_SIP:
        return "SIP";
    case WOLFSENTRY_AF_SLOW:
        return "SLOW";
    case WOLFSENTRY_AF_SCLUSTER:
        return "SCLUSTER";
    case WOLFSENTRY_AF_ARP:
        return "ARP";
    case WOLFSENTRY_AF_IEEE80211:
        return "IEEE80211";
    case WOLFSENTRY_AF_INET_SDP:
        return "INET_SDP";
    case WOLFSENTRY_AF_INET6_SDP:
        return "INET6_SDP";
    case WOLFSENTRY_AF_HYPERV:
        return "HYPERV";
    default:
        if (errcode != NULL)
            *errcode = WOLFSENTRY_ERROR_ENCODE(ITEM_NOT_FOUND);
        return NULL;
    }
}

const char *wolfsentry_addr_family_ntop(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_addr_family_t family,
    struct wolfsentry_addr_family_bynumber **addr_family,
    wolfsentry_errcode_t *errcode)
{
    wolfsentry_errcode_t ret;

    if (addr_family != NULL) {
        *addr_family = NULL;
        ret = wolfsentry_addr_family_get_bynumber_1(
            wolfsentry->addr_families_bynumber,
            family,
            addr_family);
        if (WOLFSENTRY_ERROR_CODE_IS(ret, OK)) {
            WOLFSENTRY_REFCOUNT_INCREMENT((*addr_family)->header.refcount);
            if (errcode != NULL)
                *errcode = ret;
            return (*addr_family)->byname_ent->name;
        } else if (! WOLFSENTRY_ERROR_CODE_IS(ret, ITEM_NOT_FOUND)) {
            if (errcode != NULL)
                *errcode = ret;
            return NULL;
        }
    }

    return wolfsentry_addr_family_ntop_1(family, errcode);
}

#endif /* WOLFSENTRY_PROTOCOL_NAMES */

wolfsentry_errcode_t wolfsentry_addr_family_bynumber_table_init(
    struct wolfsentry_addr_family_bynumber_table *addr_family_bynumber_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(addr_family_bynumber_table->header);
    addr_family_bynumber_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_addr_family_bynumber_key_cmp;
    addr_family_bynumber_table->header.free_fn = (wolfsentry_ent_free_fn_t)wolfsentry_addr_family_drop_reference;
    addr_family_bynumber_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNUMBER;
    WOLFSENTRY_RETURN_OK;
}

#ifndef WOLFSENTRY_PROTOCOL_NAMES
wolfsentry_errcode_t wolfsentry_addr_family_bynumber_table_clone_header(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table,
    wolfsentry_clone_flags_t flags)
{
    (void)wolfsentry;
    (void)src_table;
    (void)dest_context;
    (void)dest_table;
    (void)flags;

    WOLFSENTRY_RETURN_OK;
}
#endif /* !WOLFSENTRY_PROTOCOL_NAMES */

#ifdef WOLFSENTRY_PROTOCOL_NAMES
wolfsentry_errcode_t wolfsentry_addr_family_byname_table_init(
    struct wolfsentry_addr_family_byname_table *addr_family_byname_table)
{
    WOLFSENTRY_TABLE_HEADER_RESET(addr_family_byname_table->header);
    addr_family_byname_table->header.cmp_fn = (wolfsentry_ent_cmp_fn_t)wolfsentry_addr_family_byname_key_cmp;
    addr_family_byname_table->header.free_fn = NULL;
    addr_family_byname_table->header.ent_type = WOLFSENTRY_OBJECT_TYPE_ADDR_FAMILY_BYNAME;
    WOLFSENTRY_RETURN_OK;
}

wolfsentry_errcode_t wolfsentry_addr_family_table_clone_headers(
    struct wolfsentry_context *wolfsentry,
    struct wolfsentry_table_header *src_table1,
    struct wolfsentry_table_header *src_table2,
    struct wolfsentry_context *dest_context,
    struct wolfsentry_table_header *dest_table1,
    struct wolfsentry_table_header *dest_table2,
    wolfsentry_clone_flags_t flags)
{
    (void)wolfsentry;
    (void)src_table1;
    (void)src_table2;
    (void)dest_context;
    (void)dest_table1;
    (void)dest_table2;
    (void)flags;

    WOLFSENTRY_RETURN_OK;
}
#endif /* WOLFSENTRY_PROTOCOL_NAMES */
