# thc-rut
THC "R U There" network discovery tool - faster than most (all?).

ICMP/Ping Discovering all hosts on a Class B network takes 11 seconds. 
```
thcrut icmp -l 25000 192.168.0.1-192.168.255.254
```

ARP Discovering with 'ghosting' to hide your MAC address:
```
# thcrut arp -m de:ad:be:ef:13:37 10.0.0.0-10.0.255.254
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
 -A            ICMP Address mask request (default)
 -R            ICMP MCAST Router solicitation request
```

DHCP options:
```
 -v                  vebose
 -m <mac>            source mac (random: 00:10:05:01:0a:02)
 -D <val1[,val2]>    DHCP option, 0=List DHCP options
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
