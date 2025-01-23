/*
 * json/json_util.c
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

#include "wolfsentry/wolfsentry_json.h"
#include "wolfsentry/wolfsentry_util.h"

#define WOLFSENTRY_SOURCE_ID WOLFSENTRY_SOURCE_ID_JSON_JSON_UTIL_C

WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_centijson_errcode_translate(wolfsentry_errcode_t centijson_errcode) {
    if (WOLFSENTRY_ERROR_DECODE_SOURCE_ID(centijson_errcode) != WOLFSENTRY_SOURCE_ID_UNSET)
        WOLFSENTRY_ERROR_RERETURN(centijson_errcode);
    switch (centijson_errcode) {
    case JSON_ERR_SUCCESS: WOLFSENTRY_RETURN_OK;
    case JSON_ERR_INTERNAL:              WOLFSENTRY_ERROR_RETURN(INTERNAL_CHECK_FATAL);
    case JSON_ERR_OUTOFMEMORY:           WOLFSENTRY_ERROR_RETURN(SYS_RESOURCE_FAILED);
    case JSON_ERR_SYNTAX:                WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_BADCLOSER:             WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_BADROOTTYPE:           WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_EXPECTEDVALUE:         WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_EXPECTEDKEY:           WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_EXPECTEDVALUEORCLOSER: WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_EXPECTEDKEYORCLOSER:   WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_EXPECTEDCOLON:         WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_EXPECTEDCOMMAORCLOSER: WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_EXPECTEDEOF:           WOLFSENTRY_ERROR_RETURN(CONFIG_UNEXPECTED);
    case JSON_ERR_MAXTOTALLEN:           WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_MAXTOTALVALUES:        WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_MAXNESTINGLEVEL:       WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_MAXNUMBERLEN:          WOLFSENTRY_ERROR_RETURN(NUMERIC_ARG_TOO_BIG);
    case JSON_ERR_MAXSTRINGLEN:          WOLFSENTRY_ERROR_RETURN(STRING_ARG_TOO_LONG);
    case JSON_ERR_MAXKEYLEN:             WOLFSENTRY_ERROR_RETURN(CONFIG_INVALID_KEY);
    case JSON_ERR_UNCLOSEDSTRING:        WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_UNESCAPEDCONTROL:      WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_INVALIDESCAPE:         WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_INVALIDUTF8:           WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    case JSON_ERR_NOT_INITED:            WOLFSENTRY_ERROR_RETURN(INVALID_ARG);
#ifdef WOLFSENTRY_HAVE_JSON_DOM
    case JSON_DOM_ERR_DUPKEY:            WOLFSENTRY_ERROR_RETURN(ITEM_ALREADY_PRESENT);
#endif
    default:                             WOLFSENTRY_ERROR_RETURN(CONFIG_PARSER);
    }
}
