/*
 * $Id:$
 */

#ifndef __THCRUT_ASN_H__
#define __THCRUT_ASN_H__ 1

#ifndef ASN_SUBCAT
# define ASN_SUBCAT		((unsigned char)0x30)
#endif
#ifndef ASN_PDU
# define ASN_PDU		((unsigned char)0xa2)
#endif
#ifndef ASN_LONG_LEN
# define ASN_LONG_LEN		((unsigned char)0x80)
#endif  
#ifndef ASN_OCTET_STR
# define ASN_OCTET_STR		((unsigned char)0x04)
#endif

size_t ASN_next(uint8_t **src, int len, uint8_t *type);

#endif /* !__THCRUT_ASN_H__ */
