/*
 * $Id: default.h,v 1.5 2003/05/16 08:58:45 skyper Exp $
 */

#ifndef __THCRUT_DEFAULT_H__
#define __THCRUT_DEFAULT_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
# if defined(STDC_HEADERS) || defined(HAVE_STRING_H)
#  include <string.h>
# else
#  ifndef HAVE_STRCHR
#   ifndef strchr
#    define strchr index
#   endif
#   ifndef strrchr
#    define strrchr rindex
#   endif
#  endif
char *strchr (), *strrchr ();
#  ifndef HAVE_MEMCPY
#   ifndef memcpy
#    define memcpy(d, s, n) bcopy ((s), (d), (n))
#   endif
#   ifndef memmove
#    define memmove(d, s, n) bcopy ((s), (d), (n))
#   endif
#  endif
# endif
#else
# include <string.h>
#endif

#ifdef DEBUG
# define DEBUGF(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, a); }while(0)
#else
# define DEBUGF(a...)
#endif

#define XFREE(ptr)  do{if(ptr) free(ptr); ptr = NULL;}while(0)

#endif /* !__THCRUT_DEFAULT_H__ */
