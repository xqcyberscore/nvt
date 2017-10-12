###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service1.nasl 7402 2017-10-11 13:58:17Z cfischer $
#
# Service Detection with 'GET' Request
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17975");
  script_version("$Revision: 7402 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-11 15:58:17 +0200 (Wed, 11 Oct 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'GET' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "cifs445.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'GET' request
  to the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("dump.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

# If the service displays a banner on connection, find_service.c does not
# send a GET request. However, if a GET request was sent and the service
# remains silent, the get_http KB entry is void

r0 = get_kb_item( "FindService/tcp/" + port + "/spontaneous" ); # Banner?
get_sent = 1;

if( strlen( r0 ) > 0 ) { # We have a spontaneous banner

  get_sent = 0; # spontaneous banner => no GET request was sent by find_service

  ######## Updates for "spontaneous" banners ########
  if( r0 =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+' ) {
    debug_print( 'Fake IDENTD found on port ', port, '\n' );
    register_service( port:port, proto:"fake-identd" );
    set_kb_item( name:"fake_identd/" + port, value:TRUE );
    exit( 0 );
  }

  if( match( string:r0, pattern:'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *' ) ) {
    report_service( port:port, svc:"smsc" );
    exit( 0 );
  }

  # 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
  # 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
  # 20: 0a .
  if( ereg( pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:r0 ) ) {
    report_service( port:port, svc:"daytime" );
    exit( 0 );
  }

  # Possible outputs:
  # |/dev/hdh|Maxtor 6Y160P0|38|C|
  # |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
  if( r0 =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$' ) {
    report_service( port:port, svc:"hddtemp" );
    exit( 0 );
  }

  if( match( string:r0, pattern:'220 *FTP Server ready\r\n' ) ||
      match( string:r0, pattern:'220 *FTP server ready.\r\n' ) ) { # e.g. 220 AP9630 Network Management Card AOS v6.0.6 FTP server ready.
    report_service( port:port, svc:"ftp" );
    exit( 0 );
  }

  # 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
  # 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
  # 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
  # 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
  # 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
  # 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
  # 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
  # 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
  # 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
  # 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
  # a0: 0a 4f 4b 0d 0a .OK..
  if( match( string: r0, pattern:'"IMPLEMENTATION" "Cyrus timsieved v*"*"SASL"*' ) ) {
    register_service( port:port, proto:"sieve", message:"Sieve mail filter daemon seems to be running on this port" );
    log_message( port:port, data:"Sieve mail filter daemon seems to be running on this port" );
    exit( 0 );
  }

  # I'm not sure it should go here or in find_service2...
  if( match( string:r0, pattern:'220 Axis Developer Board*' ) ) {
    report_service( port:port, svc:"axis-developer-board" );
    exit( 0 );
  }

  if( match( string:r0, pattern:'  \x5f\x5f\x5f           *Copyright (C) 1999, 2000, 2001, 2002 Eggheads Development Team' ) ) {
    report_service( port:port, svc:"eggdrop" );
    exit( 0 );
  }

  # Music Player Daemon from www.musicpd.org
  if( ereg( string:r0, pattern:'^OK MPD [0-9.]+\n' ) ) {
    report_service( port:port, svc:"mpd" );
    exit( 0 );
  }

  if( egrep( pattern:"^OK WorkgroupShare.*server ready", string:r0 ) ) {
    report_service( port:port, svc:"WorkgroupShare" );
    exit( 0 );
  }

  # Eudora Internet Mail Server ACAP server.
  if( "* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" >< r0 ) {
    report_service( port:port, svc:"acap" );
    exit( 0 );
  }

  # Sophos Remote Messaging / Management Server
  if( "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r0 ) {
    register_service( port:port, proto:"sophos_rms", message:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
    log_message( port:port, data:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
    exit( 0 );
  }

  if( r0 =~ '^\\* *BYE ' ) {
    report_service( port:port, svc:"imap", banner:r0, message:"The IMAP server rejects connection from our host. We cannot test" );
    log_message( port:port, data:"The IMAP server rejects connection from our host. We cannot test it" );
    exit( 0 );
  }

  # General case should be handled by find_service_3digits
  if( match( string:r0, pattern:'200 CommuniGatePro PWD Server * ready*' ) ) {
    report_service( port:port, svc:"pop3pw" );
    exit( 0 );
  }

  # Should be handled by find_service already
  if( r0 =~ "^RFB [0-9]") {
    report_service( port:port, svc:"vnc" );
    replace_kb_item( name:"vnc/banner/" + port , value:r0 );
    exit( 0 );
  }

  # Keep qotd at the end of the list, as it may generate false detection
  if( r0 =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$' ) {
    register_service( port:port, proto:"qotd", message:"qotd seems to be running on this port" );
    log_message( port:port, data:"qotd seems to be running on this port" );
    exit( 0 );
  }
} # else: no spontaneous banner

###################################################

k = "FindService/tcp/" + port + "/get_http";
r = get_kb_item( k + "Hex" );
if( strlen( r ) > 0 )
  r = hex2raw( s:r );
else
  r = get_kb_item( k );

r_len = strlen( r );
if( r_len == 0 ) {
  soc = open_sock_tcp( port );
  if( ! soc )  exit( 0 );
  send( socket:soc, data:'GET / HTTP/1.0\r\n\r\n' );
  r = recv( socket:soc, length:4096 );
  close( soc );
  r_len = strlen( r );
  if( r_len == 0 ) {
    debug_print( 'Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n' );
    exit( 0 );
  }
  set_kb_item( name:k, value:r );
  if( '\0' >< r )
    set_kb_item( name:k + "Hex", value:hexstr( r ) );
}

# aka HTTP/0.9
if( r =~ '^[ \t\r\n]*<HTML>.*</HTML>' ) {
  report_service( port:port, svc:"www", banner:r );
  exit( 0 );
}

if( r == '[TS]\r\n') {
  report_service( port:port, svc:"teamspeak-tcpquery", banner:r );
  exit( 0 );
}

if( r == 'gethostbyaddr: Error 0\n' ) {
  register_service( port:port, proto:"veritas-netbackup-client", message:"Veritas NetBackup Client Service is running on this port" );
  log_message( port:port, data:"Veritas NetBackup Client Service is running on this port" );
  exit( 0 );
}

if( "GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r ||
    "GET/HTTP/1.0 : ERROR : INVALID-PORT" >< r ) { # nb: Some auth services on e.g. Windows are responding with such a different response
  report_service( port:port, svc:"auth", banner:r );
  exit( 0 );
}

if( 'Host' >< r && 'is not allowed to connect to this' >< r && ( "mysql">< tolower( r ) || "mariadb" >< tolower( r ) ) ) {
  if( "mysql">< tolower( r ) ) {
    text = "A MySQL";
  } else if( "mariadb" >< tolower( r ) ) {
    text = "A MariaDB";
  } else {
    text = "A MySQL/MariaDB";
  }
  register_service( port:port, proto:"mysql", message:text + " server seems to be running on this port but it rejects connection from the scanner." ); # or wrapped?
  log_message( port:port, data:text + " server seems to be running on this port but it rejects connection from the scanner." );
  exit( 0 );
}

# The full message is:
# Host '10.10.10.10' is blocked because of many connection errors. Unblock with 'mysqladmin flush-hosts'
if( "Host" >< r && " is blocked " >< r && "mysqladmin flush-hosts" >< r ) {
  register_service( port:port, proto:"mysql", message:"A MySQL/MariaDB server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
  log_message( port:port, data:"A MySQL server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
  exit( 0 );
}

#0x00:  4A 00 00 00 0A 35 2E 37 2E 31 36 00 68 49 72 00    J....5.7.16.hIr.
#0x10:  6A 5F 26 1F 4A 52 20 5B 00 FF FF 08 02 00 FF C1    j_&.JR [........
#0x20:  15 00 00 00 00 00 00 00 00 00 00 50 4D 51 64 16    ...........PMQd.
#0x30:  3D 50 19 35 1E 48 46 00 6D 79 73 71 6C 5F 6E 61    =P.5.HF.mysql_na
#0x40:  74 69 76 65 5F 70 61 73 73 77 6F 72 64 00 1B 00    tive_password...
#0x50:  00 01 FF 84 04 47 6F 74 20 70 61 63 6B 65 74 73    .....Got packets
#0x60:  20 6F 75 74 20 6F 66 20 6F 72 64 65 72              out of order

# or

#0x00:  3E 00 00 00 0A 35 2E 31 2E 37 31 2D 63 6F 6D 6D    >....5.1.71-comm
#0x10:  75 6E 69 74 79 00 17 ED 1F 00 29 64 41 55 68 2E    unity.....)dAUh.
#0x20:  46 58 00 FF F7 08 02 00 00 00 00 00 00 00 00 00    FX..............
#0x30:  00 00 00 00 00 69 25 7A 59 31 26 67 58 61 5D 33    .....i%zY1&gXa]3
#0x40:  24 00 1B 00 00 01 FF 84 04 47 6F 74 20 70 61 63    $........Got pac
#0x50:  6B 65 74 73 20 6F 75 74 20 6F 66 20 6F 72 64 65    kets out of orde
#0x60:  72                                                 r

if( ( "mysql_native_password" >< r && "Got packets out of order" >< r ) ||
    "001b000001ff8404476f74207061636b657473206f7574206f66206f72646572" >< hexstr( r ) ||
    "006d7973716c5f6e61746976655f70617373776f726400" >< hexstr( r ) ) {
  register_service( port:port, proto:"mysql", message:"A MySQL/MariaDB server seems to be running on this port." );
  log_message( port:port, data:"A MySQL/MariaDB server seems to be running on this port." );
  exit( 0 );
}

# JNB30........
# .4....I.n.v.a.l.i.d. .r.e.q.u.e.s.t.:. . .i.n.v.a.l.i.d. .j.n.b.b.i.n.a.r.y.
# [...]
if( r =~ "^JNB30" && ord( r[5] ) == 14 && ord( r[6] == 3 ) ) {
  register_service( port:port, proto:"jnbproxy", message:"ColdFusion jnbproxy is running on this port." );
  log_message( port:port, data:"ColdFusion jnbproxy is running on this port." );
  exit( 0 );
}

if( "Asterisk Call Manager" >< r ) {
  register_service( port:port, proto:"asterisk", message:"An Asterisk Call Manager server is running on this port." );
  log_message( port:port, data:"An Asterisk Call Manager server is running on this port." );
  exit( 0 );
}

# Taken from find_service2
if( r_len == 3 && ( r[2] == '\x10' || # same test as find_service
                   r[2] == '\x0b' ) ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' ) {
  register_service( port:port, proto:"msdtc", message:"A MSDTC server seems to be running on this port");
  log_message( port:port, data:"A MSDTC server seems to be running on this port");
  exit( 0 );
}

# It seems that MS DTC banner is longer that 3 bytes, when we properly handle
# null bytes
# For example:
# 00: 90 a2 0a 00 80 94 ..
if( (r_len == 5 || r_len == 6) && r[3] == '\0' &&
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0' ) {
  register_service( port:port, proto:"msdtc", message:"A MSDTC server seems to be running on this port");
  log_message( port:port, data:"A MSDTC server seems to be running on this port");
  exit( 0 );
}

if( r == '\x01Permission denied' || ( "lpd " >< r && "Print-services" >< r )  ) {
  report_service( port:port, svc:"lpd", message:"An LPD server is running on this port" );
  log_message( port:port, data:"An LPD server is running on this port" );
  exit( 0 );
}

#### Double check: all this should be handled by find_service.nasl ####

if( r == 'GET / HTTP/1.0\r\n\r\n' ) {
  report_service( port:port, svc:"echo", banner:r );
  exit( 0 );
}

# Should we excluded port=5000...? (see find_service.c)
if( r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ' ) {
  report_service( port:port, svc:"www", banner:r );
  exit( 0 );
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if( r =~ '^[0-9][0-9][0-9]-?[ \t]' ) {
  debug_print('"3 digits" found on port ', port, ' in response to GET\n' );
  register_service( port:port, proto:"three_digits" );
  exit( 0 );
}

if( r =~ "^RFB [0-9]" ) {
  report_service( port:port, svc:"vnc" );
  replace_kb_item( name:"vnc/banner/" + port , value:r );
  exit( 0 );
}

if( match( string:r, pattern:"Language received from client:*Setlocale:*" ) ) {
  report_service( port:port, svc:"websm" );
  exit( 0 );
}

#invalid command (code=12064, len=1414541105)
if( egrep( string:bin2string( ddata:r, noprint_replacement:' ' ), pattern:"invalid command \(code=([0-9]+), len=([0-9]+)\)" ) ) {
  register_service( port:port, proto:"sphinxapi", message:"A Sphinx search server seems to be running on this port" );
  log_message( port:port, data:"A Sphinx search server seems to be running on this port" );
  exit( 0 );
}

#2.0.9-id64-release (rel20-r4115) or 2.1.2-id64-release (r4245)
if( egrep( string:bin2string( ddata:r, noprint_replacement:' ' ), pattern:"([0-9.]+)-id([0-9]+)-release \(([0-9a-z\-]+)\)" ) ) {
  register_service( port:port, proto:"sphinxql", message:"A Sphinx search server (MySQL listener) seems to be running on this port" );
  log_message( port:port, data:"A Sphinx search server (MySQL listener) seems to be running on this port" );
  exit( 0 );
}

if( match( string:r, pattern:"*<stream:stream*xmlns:stream='http://etherx.jabber.org/streams'*" ) ) {
  if( "jabber:server" >< r ) {
    register_service( port:port, proto:"xmpp-server", message:"A XMPP server-to-server service seems to be running on this port" );
    log_message( port:port, data:"A XMPP server-to-server service seems to be running on this port" );
    exit( 0 );
  } else if( "jabber:client" >< r ) {
    register_service( port:port, proto:"xmpp-client", message:"A XMPP client-to-server service seems to be running on this port" );
    log_message( port:port, data:"A XMPP client-to-server service seems to be running on this port" );
    exit( 0 );
  } else {
    log_message( port:port, data:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    register_service( port:port, proto:"xmpp-server", message:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    register_service( port:port, proto:"xmpp-client", message:"A XMPP client-to-server or server-to-server service seems to be running on this port" );
    exit( 0 );
  }
}

if( "Active Internet connections" >< r || "Active connections" >< r ) {
  register_service( port:port, proto:"netstat", message:"A netstat service seems to be running on this port." );
  log_message( port:port, data:"A netstat service seems to be running on this port." );
  exit( 0 );
}

if( "obby_welcome" >< r ) {
  register_service( port:port, proto:"obby", message:"A obby service seems to be running on this port." );
  log_message( port:port, data:"A obby service seems to be running on this port." );
  exit( 0 );
}

if( match( string:r, pattern:"*OK Cyrus IMSP version*ready*" ) ) {
  register_service( port:port, proto:"imsp", message:"A Cyrus IMSP service seems to be running on this port." );
  log_message( port:port, data:"A Cyrus IMSP service seems to be running on this port." );
  exit( 0 );
}

# e.g.  RESPONSE/None/53/application/json: {"status": 554, "message": "Unparsable message body"}
if( match( string:r, pattern:'RESPONSE/None/*/application/json:*{"status": *, "message": "*"}' ) ) {
  register_service( port:port, proto:"umcs", message:"A Univention Management Console Server service seems to be running on this port." );
  log_message( port:port, data:"A Univention Management Console Server service seems to be running on this port." );
  exit( 0 );
}

if( "DRb::DRbConnError" >< bin2string( ddata:r ) ) {
  register_service( port:port, proto:"drb", message:"A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
  log_message( port:port, data:"A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
  exit( 0 );
}

# 9290 for raw scanning to peripherals with IEEE 1284.4 specifications. On three port HP JetDirects, the scan ports are 9290, 9291, and 9292.
# (When you connect to a raw scan port, the scan gateway sends back "00" if the connection to the peripheral's scan service was successful, "01"
# if somebody else is using it, and "02" if some other error, for example, the supported peripheral is not connected. Ports 9220, 9221, and 9222
# are the generic scan gateway ports currently only usable on 1284.4 peripherals.)
# Source: http://www2.cruzio.com/~jeffl/sco/lp/printservers.htm
if( port =~ "^929[0-2]$" && r =~ "^0[0-2]$") {
  register_service( port:port, proto:"iee-rsgw", message:"A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
  log_message( port:port, data:"A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
  exit( 0 );
}

if( port == 515 && hexstr( r ) =~ "^ff$") {
  register_service( port:port, proto:"printer", message:"A LPD service seems to be running on this port." );
  log_message( port:port, data:"A LPD service seems to be running on this port." );
  exit( 0 );
}

if( "(Thread" >< r && ( "Notify Wlan Link" >< r ||
    "Received unknown command on socket" >< r ||
    "fsfsFlashFileHandleOpen" >< r ||
    "Found existing handle" >< r ) ) {
  register_service( port:port, proto:"wifiradio-setup", message:"A WiFi radio setup service seems to be running on this port." );
  log_message( port:port, data:"A WiFi radio setup service seems to be running on this port." );
  exit( 0 );
}

# Sophos Remote Messaging / Management Server
if( "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r ) {
  register_service( port:port, proto:"sophos_rms", message:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  log_message( port:port, data:"A Sophos Remote Messaging / Management Server seems to be running on this port." );
  exit( 0 );
}

# Check_MK Agent
if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  # Check_MK Agents seems to not answer to repeated requests in a short amount of time so saving the response here for later processing.
  replace_kb_item( name:"check_mk_agent/banner/" + port, value:r );
  register_service( port:port, proto:"check_mk_agent", message:"A Check_MK Agent seems to be running on this port." );
  log_message( port:port, data:"A Check_MK Agent seems to be running on this port." );
  exit( 0 );
}

if( r =~ "^\.NET" && ( "customErrors" >< r || "RemotingException" >< r ) ) {
  register_service( port:port, proto:"remoting", message:"A .NET remoting service seems to be running on this port." );
  log_message( port:port, data:"A .NET remoting service seems to be running on this port." );
  exit( 0 );
}

if( ( r =~ "^-ERR wrong number of arguments for 'get' command" && "-ERR unknown command 'Host:'" >< r ) ||
    r =~ "^-DENIED Redis is running in protected mode" ) {
  register_service( port:port, proto:"redis", message:"A Redis server seems to be running on this port." );
  log_message( port:port, data:"A Redis server seems to be running on this port." );
  exit( 0 );
}

#### Some spontaneous banners are coming slowly, so they are wronly
#### registered as answers to GET
if( r =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$' ) {
  report_service( port:port, svc:"hddtemp" );
  exit( 0 );
}

exit( 0 );
