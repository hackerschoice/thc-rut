dnl THCRUT configure.in, anonymous@segfault.net
dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
AC_INIT([thc-rut], 2.2.6-rc1)
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_SYSTEM

dnl we use automake
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)
dnl for --enable-maintainer-mode fun use:
dnl AM_MAINTAINER_MODE 

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
dnl
dnl Use these compiler flags if we have gcc.
dnl
if test $ac_cv_prog_gcc = yes; then
  CCOPTS='-O2 -Wall -g'
  CFLAGS="$CCOPTS"
fi
test "x$prefix" != "xNONE" || prefix="/usr/local"
test "x$exec_prefix" != "xNONE" || exec_prefix="${prefix}"
trydir_i="${prefix}/include"
trydir_l="${prefix}/lib"

if test "${prefix}" != "/usr/local" ; then
	trydir_i="${trydir_i} /usr/local/include"
	trydir_l="${trydir_l} /usr/local/lib"
fi

trydir_i="${trydir_i} ${prefix}/include/pcap ${prefix}/include/pcre /usr/include/pcre /usr/include/pcap" 
AC_ARG_WITH(includes,
[  --with-includes=DIR     Space-seperated list of include directories],
[
	trydir_i="$trydir_i ${withval}"
])
for xincdir in $trydir_i ; do
	if test ! -d "$xincdir" ; then
		continue;
	fi
	if test x"${INCLUDES}" = x; then
		INCLUDES="-I${xincdir}";
	else
		INCLUDES="$INCLUDES -I${xincdir}";
	fi
done
CPPFLAGS="${INCLUDES} $CPPFLAGS"

dnl Add available library directories
trydir_l="${trydir_l} ${prefix}/lib/pcap"
AC_ARG_WITH(libs,
[  --with-libs=DIR         Space-seperated list of library directories],
[
	trydir_l="$trydir_l ${withval}"
])
for xlibdir in $trydir_l ; do
	if test ! -d "$xlibdir" ; then
		continue;
	fi
	if test x"${LIBDIR}" = x; then
		LIBDIR="-L${xlibdir}";
	else
		LIBDIR="$LIBDIR -L${xlibdir}";
	fi
done
LDFLAGS="${LIBDIR} $LDFLAGS"

dnl Check OS dependent stuff
dnl select on FreeBSD <=4.6 never indicated that there is data to read.
case "$target_os" in
*freebsd*)
	echo "############################################################"
	echo "### Some FreeBSDs' have a broken SELECT-BPF"
	echo "### implementation (see tcpdump mailinglist)."
	echo "### THC RUT might not work at all on such a platform."
	echo "### continueing in 10 seconds. Good luck!"
	echo "############################################################"
	sleep 10
	dnl AC_DEFINE(THCRUT_BROKEN_BPF_SELECT, 1, [def])
	;;
esac

dnl Checks for libraries.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB([net], [libnet_name_resolve], [AC_MSG_ERROR([libnet 1.0.x found. Requires libnet 1.1 or newer])])
AC_CHECK_LIB([net], [libnet_init], ,[AC_MSG_ERROR([libnet 1.1.x not found])])


dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/time.h unistd.h string.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_MEMCMP

AC_TYPE_SIGNAL
dnl If size_t is not defined, define size_t to be unsigned. 
AC_TYPE_SIZE_T 
dnl If uid_t is not defined, define uid_t to be int and gid_t to be int.
AC_TYPE_UID_T

dnl check if we are on a bigendian b0x
dnl We dont check for this because autoconf maintainers are pussies and
dnl yell a warning everytime. Guys, introduce AC_C_BIGENDIAN_CROSS for
dnl gods sake!
dnl AC_C_BIGENDIAN

AC_CHECK_FUNCS(gettimeofday memcpy strchr strlcpy)
dnl FIXME: repair this later
dnl SNPRINTF=''
dnl AC_CHECK_FUNC(snprintf, AC_DEFINE(HAVE_SNPRINTF), SNPRINTF='snprintf.o')
dnl AC_SUBST(SNPRINTF)

AC_MSG_CHECKING(whether to enable leeto mode)
AC_ARG_ENABLE(leeto, 
[  --enable-leeto          Enable extrem 31337 mode.],
[ case "$enableval" in
  yes)
    AC_MSG_RESULT(y0y0)
    AC_DEFINE(WITH_LEETO, 1, [31337])
     ;;
  *)
    AC_MSG_RESULT(nope)
    ;;
  esac ],
  AC_MSG_RESULT(nope)
)

AC_ARG_ENABLE(debug,
[  --enable-debug          Enable debug information],
	AC_DEFINE(DEBUG, 1, [Debug infos])
)

AC_ARG_ENABLE(static,
[  --enable-static          Compile static binary],
        [STATIC="yes"], [STATIC="no"]
)

if test x"$STATIC" = x"yes"; then
	CFLAGS="-static ${CFLAGS}"
	LIBS="${LIBS} -lpthread"
fi

AC_ARG_ENABLE(dist,
[  --enable-dist           Enable distribution mode, Use own libraries.],
	[DIST="yes"], [DIST="no"]
)

AC_CHECK_LIB(pcap, pcap_open_live,, AC_MSG_ERROR(We need libpcap.
Get libpcap from http://www.tcpdump.org or try --with-[[libs,includes]]=DIR))

AC_CHECK_LIB(pcre, pcre_compile,, AC_MSG_ERROR(We need libpcre.))

dnl AC_CHECK_LIB(pcre, pcre_compile, [PCRE=yes], [PCRE=no])
dnl if test x"$PCRE" = x"no" -o x"$DIST" = x"yes"; then
dnl	AC_CONFIG_SUBDIRS(pcre-3.9)
dnl	THCRUT_SUBDIRS="$THCRUT_SUBDIRS pcre-3.9"
dnl	CPPFLAGS="-I../pcre-3.9 ${CPPFLAGS}"
dnl	LDFLAGS="-L../pcre-3.9 ${LDFLAGS}"
dnl	PRG_PCRE_CONFIG_CFLAGS="../pcre-3.9/pcre-config --cflags"
dnl	PRG_PCRE_CONFIG_LIBS="../pcre-3.9/pcre-config --libs"
dnl else
dnl 	dnl Into CFLAGS and not CPPFLAGS because it's --cflags
dnl	CFLAGS="`pcre-config --cflags` $CFLAGS"
dnl	LIBS="`pcre-config --libs` $LIBS"
dnl fi

dnl config/Makefile required for 'make dist'
B=`eval echo ${bindir}` ; B=`eval echo ${B}`
D=`eval echo ${sysconfdir}` ; D=`eval echo ${D}`
THCRUT_DATADIR=`eval echo ${datadir}/thcrut` ; THCRUT_DATADIR=`eval echo ${THCRUT_DATADIR}`
AC_DEFINE_UNQUOTED(THCRUT_DATADIR, "${THCRUT_DATADIR}", [share/thcrut])

dnl disable NMAP until we have it inside thcrut-os-fingerprints file.
dnl AC_DEFINE(WITH_NMAPFP, 1, [def])

#AC_SUBST(THCRUT_SUBDIRS)
AC_SUBST(PRG_PCRE_CONFIG_CFLAGS)
AC_SUBST(PRG_PCRE_CONFIG_LIBS)
AC_OUTPUT(Makefile src/Makefile)

dnl Just to show the correct values...
dnl CFLAGS="`${srcdir}/pcre-3.9/pcre-config --cflags` $CFLAGS"
dnl LIBS="`${srcdir}/pcre-3.9/pcre-config --libs` $LIBS"

echo "
THCrut has been configured with the following options:
                 User binaries: $B
                Data directory: $THCRUT_DATADIR

              Host: ${host}
          Compiler: ${CC}
    Compiler flags: ${CFLAGS}
Preprocessor flags: ${CPPFLAGS}
      Linker flags: ${LDFLAGS}
         Libraries: ${LIBS}"
cat ${srcdir}/thcrutlogo.txt
echo "Configuration complete. Now type: make all install; thc-rut -h"

