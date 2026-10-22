/*
 * wolfsentry_config.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*! @file wolfsentry_config.h
    \brief Format-independent configuration loader options.
 */

#ifndef WOLFSENTRY_CONFIG_H
#define WOLFSENTRY_CONFIG_H

#ifndef WOLFSENTRY_NO_STDINT_H
#include <stdint.h>
#endif

/*
 * Optional configuration loader profiles.  Each disabled section is rejected
 * as an invalid configuration key rather than being silently ignored.
 *
 * WOLFSENTRY_CONFIG_NO_ROUTES omits static route loading.
 * WOLFSENTRY_CONFIG_NO_ADDR_FAMILY_NAMES requires numeric route families.
 * WOLFSENTRY_CONFIG_NO_ROUTE_ENDPOINTS omits remote and local route endpoints.
 * WOLFSENTRY_CONFIG_NO_EVENTS omits event loading.
 * WOLFSENTRY_CONFIG_NO_USER_VALUES omits user-value loading.
 * WOLFSENTRY_CONFIG_NO_EVENTCONFIG omits global and per-event configuration.
 * WOLFSENTRY_CONFIG_NO_TRANSACTIONS omits clone, dry-run, and commit support.
 * WOLFSENTRY_CONFIG_NO_LEGACY_EVENT_SYNTAX omits pre-1.4 event aliases.
 * WOLFSENTRY_CONFIG_NO_TEXT_NUMBERS requires native CBOR numeric values.
 * WOLFSENTRY_CONFIG_NO_TEXT_ADDRESSES requires native CBOR byte-string addresses.
 * WOLFSENTRY_CONFIG_NO_ERROR_MESSAGES omits detailed parser error messages.
 * WOLFSENTRY_CONFIG_MINIMAL enables the four section-omission options.
 */
#ifdef WOLFSENTRY_CONFIG_MINIMAL
    #ifndef WOLFSENTRY_CONFIG_NO_ROUTES
        #define WOLFSENTRY_CONFIG_NO_ROUTES
    #endif
    #ifndef WOLFSENTRY_CONFIG_NO_EVENTS
        #define WOLFSENTRY_CONFIG_NO_EVENTS
    #endif
    #ifndef WOLFSENTRY_CONFIG_NO_USER_VALUES
        #define WOLFSENTRY_CONFIG_NO_USER_VALUES
    #endif
    #ifndef WOLFSENTRY_CONFIG_NO_EVENTCONFIG
        #define WOLFSENTRY_CONFIG_NO_EVENTCONFIG
    #endif
#endif

typedef uint32_t wolfsentry_config_load_flags_t;
    /*!< \brief Type for holding flag bits from #wolfsentry_config_load_flags. */

/*! \brief Flags to be `OR`d together to control configuration loading. */
enum wolfsentry_config_load_flags {
    WOLFSENTRY_CONFIG_LOAD_FLAG_NONE             = 0U,
        /*!< \brief Use the default behavior. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_FLUSH         = 1U << 0U,
        /*!< \brief Add to the current configuration instead of replacing it. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_DRY_RUN          = 1U << 1U,
        /*!< \brief Test the load without updating the current configuration. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_LOAD_THEN_COMMIT = 1U << 2U,
        /*!< \brief Load into a clone before replacing the current configuration. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_NO_ROUTES_OR_EVENTS = 1U << 3U,
        /*!< \brief Skip routes and events in the supplied configuration. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_ABORT = 1U << 4U,
        /*!< \brief Reject duplicate keys in structured user values. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USEFIRST = 1U << 5U,
        /*!< \brief Keep the first duplicate key in structured user values. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_DUPKEY_USELAST = 1U << 6U,
        /*!< \brief Keep the last duplicate key in structured user values. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_JSON_DOM_MAINTAINDICTORDER = 1U << 7U,
        /*!< \brief Retain dictionary insertion order in structured user values. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_FLUSH_ONLY_ROUTES = 1U << 8U,
        /*!< \brief Flush routes while retaining events and user values. @hideinitializer */
    WOLFSENTRY_CONFIG_LOAD_FLAG_FINI             = 1U << 30U
        /*!< \brief Reserved for internal use. @hideinitializer */
};

#endif /* WOLFSENTRY_CONFIG_H */
