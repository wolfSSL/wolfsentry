/*!
   \brief Return the protocol family ID for a family name

   \param family_name the family name
   \param family_name_len the length of family_name

   \returns the family ID, WOLFSENTRY_AF_UNSPEC on no match
*/
wolfsentry_family_t wolfsentry_family_pton(const char *family_name, size_t family_name_len);

/*!
   \brief Return the protocol name for a family ID

   \param family the family ID

   \returns the family name
*/
const char *wolfsentry_family_ntop(wolfsentry_family_t family);
