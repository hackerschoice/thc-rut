bin_PROGRAMS = thc-rut
thc_rut_SOURCES = nvt.c icmp_main.c arp_main.c thcrut_libnet.c dhcp_main.c system.c fp.c discover_dispatch.c packets.c nmap_compat.c thcrut_pcap.c network.c discover_main.c thcrut_sig.c state.c arpg.c dhcp.c network_raw.c schedule.c dcd_icmp.c macvendor.c range.c thc-rut.c asn.c tty.c
noinst_HEADERS = nvt.h icmp_main.h arp_main.h thcrut_libnet.h dhcp_main.h system.h fp.h discover_dispatch.h packets.h nmap_compat.h thcrut_pcap.h network.h discover_main.h state.h arpg.h dcd_icmp.h dhcp.h macvendor.h network_raw.h range.h schedule.h default.h thc-rut.h thcrut_sig.h asn.h tty.h
## use thcrutdir = /etc here if you dont like /usr/local/etc...
thcrutdir = $(sysconfdir)
EXTRA_DIST = manuf nmap-os-fingerprints thcrut-os-fingerprints
pkgdata_DATA = manuf nmap-os-fingerprints thcrut-os-fingerprints
AM_CFLAGS = `@PRG_LIBNET_CONFIG_CFLAGS@` `@PRG_PCRE_CONFIG_CFLAGS@`
LIBS = @LIBS@ `@PRG_LIBNET_CONFIG_LIBS@` `@PRG_PCRE_CONFIG_LIBS@`

