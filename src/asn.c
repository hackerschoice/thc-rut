/*
 * $Id:$
 */

#include "default.h"
#include <sys/types.h>
#include "asn.h"

/*
 * Return the length of an ASN.1 object starting at *src.
 * Store the pointer to the ASN.1 data in src.
 * Return the type in *type.
 *
 * SUB categories _and_ PDU's are ignored.
 *
 * Next call should be done with src + olen.
 *
 * Return 0 on error.
 */
size_t
ASN_next(uint8_t **data, int len, uint8_t *type)
{
	uint8_t *src = *data;
	uint8_t *end = src + len;

	size_t olen;

	if (end - src < 2)
		goto err;

	*type = *src++;

	while ((*type == ASN_SUBCAT) || (*type == ASN_PDU))
	{
		if (*src++ & ASN_LONG_LEN)
			src++;
		
		if (end - src < 2)
			goto err;
		*type = *src++;
	}

	if (*src & ASN_LONG_LEN)
		olen = (*src++ & ~ASN_LONG_LEN) << 8;
	else
		olen = 0;

	if (end - src < 1)
		goto err;

	olen += *src++;

	if (olen > end - src)
		goto err;

	*data = src;

	return olen;
err:
	*data = NULL;
	return 0;
}

