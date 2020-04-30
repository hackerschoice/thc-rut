/*
 * Vendor <-> mac 
 * RUT, anonymous@segfault.net
 */

#ifndef THCRUT_MACVENDOR_H
#define THCRUT_MACVENDOR_H 1


const char *MacVendor_by_mac(uint8_t *mac);

char *mac2vendor(unsigned char *tag);

#endif /* !THCRUT_MACVENDOR_H */

