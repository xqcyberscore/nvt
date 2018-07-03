###############################################################################
# OpenVAS Vulnerability Test
# $Id: telnet.nasl 10381 2018-07-03 08:49:51Z cfischer $
#
# Check for Telnet Server
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100074");
  script_version("$Revision: 10381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-03 10:49:51 +0200 (Tue, 03 Jul 2018) $");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for Telnet Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  # nb: Makes sure that this NVT is running late as it is often mis-identifying services as Telnet (see no_telnet below)
  script_dependencies("unknown_services.nasl", "find_service_nmap.nasl");
  script_require_ports("Services/unknown", "Services/telnet");
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"summary", value:"A telnet Server is running at this host.

   Experts in computer security, such as SANS Institute, and the members of the
   comp.os.linux.security newsgroup recommend that the use of Telnet for remote
   logins should be discontinued under all normal circumstances, for the following
   reasons:

   * Telnet, by default, does not encrypt any data sent over the connection
     (including passwords), and so it is often practical to eavesdrop on the
     communications and use the password later for malicious purposes; anybody who
     has access to a router, switch, hub or gateway located on the network between
     the two hosts where Telnet is being used can intercept the packets passing by
     and obtain login and password information (and whatever else is typed) with any
     of several common utilities like tcpdump and Wireshark.

   * Most implementations of Telnet have no authentication that would ensure
     communication is carried out between the two desired hosts and not intercepted
     in the middle.

   * Commonly used Telnet daemons have several vulnerabilities discovered over
     the years.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("telnet_func.inc");

no_telnet = make_list( "<<<check_mk>>>", "\\check_mk\.ini", "<<<uptime>>>", "<<<services>>>", "<<<mem>>>", "Check_MK_Agent",
                       " stopped/demand ", " running/auto ", " stopped/disabled ", # Check_MK Agent
                       "NOTIC: iSCSI:", "INFOR: iSCSI:", "ERROR: iSCSI:", # DELL TL2000/TL4000 iSCSI-SAS Bridge on 1234/tcp
                       "Press Enter for Setup Mode", "^ATQ", "HSQLDB JDBC Network Listener",
                       "^OK MPD", "^IOR:", "Host.*is not allowed to connect to this (MySQL|MariaDB) server",
                       "Host.*is blocked.*mysqladmin flush-hosts",
                       "mysql_native_password",
                       "Where are you?", #rexecd
                       "DOCTYPE GANGLIA_XML", # Ganglia gmetad daemon
                       "^Asterisk Call Manager",
                       "^w0256", # Unknown service on 10003/tcp
                       "java\.rmi\.MarshalledObject",
                       "<\?xml version=", # Unknown service on 5547/tcp
                       "\-nthreads", "NServer:", # Unknown service on 34903/tcp
                       "^ERROR :Closing Link:.*Throttled: Reconnecting too fast", # unlrealircd
                       "^:.*NOTICE (Auth|AUTH).*Looking up your hostname", # unlrealircd
                       "^TDMM", # LANDesk Targeted Multicast Service, 33354/tcp
                       "^UDMM", # Unknown LANDesk Service, 33354/tcp
                       "\+HELLO v([0-9.]+) \$Name:", # e.g. +HELLO v1.1 $Name:  $, unknown service on 5600/tcp
                       "^ getnameinfo: Temporary failure in name resolution $", # rsh on 514/tcp, spaces at the begin and end are expected
                       "Welcome to the TeamSpeak 3 ServerQuery interface",
                       "500 OOPS: could not bind listening IPv4 socket", # Probably PureFTPd
                       "^ncacn_http/1\.0",
                       "^220 .*FTP [Ss]erver .*ready",
                       "^220 .*Ready for user login\.", # VIBNODE FTP
                       "^220 Service ready",
                       "^RFB 00[0-9]\.00[0-9]", # VNC
                       "\(Eggdrop v.* Eggheads\)" ); # Eggdrop Bot

function no_telnet_banner( banner ) {

  local_var banner, nt;

  if( ! banner ) return TRUE;

  foreach nt( no_telnet ) {
    if( egrep( pattern:nt, string:banner ) )
      return TRUE;
  }
  return;
}

port = get_all_tcp_ports();

# nb: We still want to collect / report the data below for
# services detected as telnet by find_service.nasl...
if( ! verify_service( port:port, proto:"telnet" ) &&
    ! service_is_unknown( port:port ) ) {
  exit( 0 );
}

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

banner = telnet_negotiate( socket:soc );
close( soc );

if( ! banner ) exit( 0 );
if( strlen( banner ) < 4 ) exit( 0 );
banner = bin2string( ddata:banner, noprint_replacement:' ' );
if( ! banner || banner =~ '^[ \r\n]*$' ) exit( 0 );
if( no_telnet_banner( banner:banner ) ) exit( 0 );

if( "login:" >!< tolower( banner ) )
  set_kb_item( name:'telnet/' + port + '/no_login_banner', value:TRUE ); # for check_account()

register_service( port:port, proto:"telnet", message:"A telnet server seems to be running on this port" );
set_telnet_banner( port:port, banner:banner );
set_kb_item( name:"telnet/banner/available", value:TRUE );

log_message( port:port, data:'A telnet server seems to be running on this port' );

exit( 0 );
