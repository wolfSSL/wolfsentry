/*!
   \brief Initialize the JSON configuration object

   \param wolfsentry the wolfsentry object
   \param load_flags the configuration loading flags
   \param jps the initialized JSON process state

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_init(
    struct wolfsentry_context *wolfsentry,
    wolfsentry_config_load_flags_t load_flags,
    struct wolfsentry_json_process_state **jps);

/*!
   \brief Set the default JSON parser default config

   \param jps the JSON process state
   \param config the configuration to set

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_set_default_config(
    struct wolfsentry_json_process_state *jps,
    struct wolfsentry_eventconfig *config);

/*!
   \brief Send data into the JSON parser

   \param jps the JSON process state
   \param json_in the data to insert into the parser
   \param json_in_len the length of the json_in
   \param err_buf a pointer to a buffer for error messages
   \param err_buf_size the size of err_buf

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_config_json_fini
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_feed(
    struct wolfsentry_json_process_state *jps,
    const char *json_in,
    size_t json_in_len,
    char *err_buf,
    size_t err_buf_size);

/*!
   \brief Get the error code and message from the JSON parser

   \param jps the JSON process state
   \param json_errcode the returned error code
   \param json_errmsg the returned error message

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_centijson_errcode(struct wolfsentry_json_process_state *jps, int *json_errcode, const char **json_errmsg);

/*!
   \brief Finialize processing the JSON data started with wolfsentry_config_json_feed

   \param jps the JSON process state
   \param err_buf a pointer to a buffer for error messages
   \param err_buf_size the size of err_buf

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success

   \sa wolfsentry_config_json_feed
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_fini(
    struct wolfsentry_json_process_state **jps,
    char *err_buf,
    size_t err_buf_size);

/*!
   \brief Process the an entired JSON buffer in a single shot instead of parts

   \param json_in the JSON text to parse
   \param json_in_len the length of json_in
   \param load_flags the flags for the JSON loading
   \param err_buf a pointer to a buffer for error messages
   \param err_buf_size the size of err_buf

   \returns When decoded using WOLFSENTRY_ERROR_DECODE_ERROR_CODE(), WOLFSENTRY_ERROR_ID_OK on success
*/
WOLFSENTRY_API wolfsentry_errcode_t wolfsentry_config_json_oneshot(
    struct wolfsentry_context *wolfsentry,
    const char *json_in,
    size_t json_in_len,
    wolfsentry_config_load_flags_t load_flags,
    char *err_buf,
    size_t err_buf_size);
