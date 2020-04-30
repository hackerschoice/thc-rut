# thc-rut
THC "R U There" network discovery tool - faster than most (all?).

2003 - Original release 
2020 - Ported to MacOS, FreeBSD, Linux and Libnet-1.3 

ICMP/Ping all hosts on a Class B network takes **11 seconds**. 
```
thc-rut icmp -l 25000 192.168.0.1-192.168.255.254
```

ICMP/Ping hosts that are firewalled (using ICMP timestamp requests instead)
```
# thc-rut icmp -T 
```

ARP/Ping all hosts on the local network:
```
# thc-rut arp
192.168.1.1      b4:fb:e4:e5:a5:d5 Ubiquiti Networks Inc.
192.168.1.190    6c:4d:73:d4:b6:da Apple, Inc.
192.168.1.38     e0:46:9a:31:01:d4 Netgear
192.168.1.105    c4:67:b5:33:b1:70 Libratone A/S
192.168.1.106    3e:97:69:5a:53:f8 Intel Corporate
192.168.1.45     00:17:88:71:d7:e6 Philips Lighting BV
```

ARP/Ping using a 'ghost' MAC (mac spoofing):
```
# thc-rut arp -m de:ad:be:ef:13:37 10.0.0.0-10.0.255.254
```

DHCP test requests:
```
# thc-rut dhcp
```

DHCP Denial-Of-Service (exhaust DHCP server and prevent anyone else from joining the network):
```
# thc-rut -F dhcp -m 0
```

All Commands:
```
 discover        Host discovery and OS fingerprinting
 icmp            ICMP discovery
 dhcp            DHCP discovery
 arp             ARP discovery
```

ICMP options:
```
 -P            ICMP echo request (default)
 -T            ICMP Timestamp Request
 -A            ICMP Address mask request (obsolete)
 -R            ICMP MCAST Router solicitation request
 ```

DHCP options:
```
 -m <mac>            source mac (interace's default or -m 0 for random)
 -d <mac>            destination mac (default: broadcast)
 -D <val1[,val2]>    DHCP option, 0=List DHCP options, all=ALL (!)
```

ARP options:
```
-m <mac>            source MAC (source interface)
```

DISCOVER options:
```
 -d          Don't do host discovery (tcp-sync ping, ...)
 -O          With OS Fingerprinting
 -v          verbose output (fingerprint stamps)
 -l <n>      Hosts in parallel (default: 5000)
 ```

Blast from the past:
```
                                                                           _
                                                                         _( (~\
                  _ _                        /                          ( \> > \
              -/~/ / ~\                     :;                \       _  > /(~\/
             || | | /\ ;\                   |l      _____     |;     ( \/    > >
--------.    _\\)\)\)/ ;;;                  `8o __-~     ~\   d|      \      //
* HELP * |  ///(())(__/~;;\                  "88p;.  -. _\_;.oP        (_._/ /
* HELP * | (((__   __ \\   \                  `>,% (\  (\./)8"         ;:'  i
         | )))--`.'-- (( ;,8 \               ,;%%%:  ./V^^^V'          ;.   ;.
I'M JUST | ((\   |   /)) .,88  `: ..,,;;;;,-::::::'_::\   ||\         ;[8:   ;
STUPID   !  )|  ~-~  |(|(888; ..``'::::8888oooooo.  :\`^^^/,,~--._    |88::  |
WHITEHAT.|_____-===- /|  \8;; ``:.      oo.8888888888:`((( o.ooo8888Oo;:;:'  |
         |. |_~-___-~_|   `-\.   `        `o`88888888b` )) 888b88888P""'     ;
PLEASE    | ; ~~~~;~~         "`--_`.       b`888888888;(.,"888b888"  ..::;-'
DONT HURT |   ;      ;              ~"-....  b`8888888:::::.`8888. .:;;;''
MEEEEEE!  |      ;    ;                 `:::. `:::OOO:::::::.`OO' ;;;''
          | :       ;                     `.      "``::::::''    .'
* HELP *  |    ;                           `.   \_              /
* HELP *  |  ;       ;                       +:   ~~--  `:'  -';
__________!                                   `:         : .::/  -Tua Xiong
                 ;                            ;;+_  :::. :..;;;
-=[ (C) THE HACKERS CHOICE - Estd. 1995 ]=- -=[ www.ircsnet.net /j #THC ]=-
------=[ WHQ: http://www.thc.org ]=- - -=[ Enjoy your enemy... ]=----------
```
