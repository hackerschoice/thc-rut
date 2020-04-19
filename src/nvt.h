/*
 * $Id: nvt.h,v 1.1 2003/05/15 12:13:49 skyper Exp $
 */


#ifndef __THCRUT_NVT_H__
#define __THCRUT_NVT_H__ 1

#define NVT_SE          0xf0
#define NVT_SB          0xfa
#define NVT_WILL        0xfb
#define NVT_WONT        0xfc
#define NVT_DO          0xfd
#define NVT_DONT        0xfe
#define NVT_IAC         0xff

int NVT_decode(char *data, int len, char *ans, int *alen, char *rem, int *rlen);

#endif /* !__THCRUT_NVT_H__ */
