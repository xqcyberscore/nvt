###############################################################################
# OpenVAS Vulnerability Test
# $Id: telnet.nasl 13339 2019-01-29 09:38:43Z cfischer $
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
  script_version("$Revision: 13339 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-29 10:38:43 +0100 (Tue, 29 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check for Telnet Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  # nb: Makes sure that this NVT is running late as it is often mis-identifying services as Telnet (see telnet_verify_banner)
  script_dependencies("unknown_services.nasl", "find_service_nmap.nasl");
  script_require_ports("Services/unknown", "Services/telnet");
  script_mandatory_keys("TCP/PORTS");

  script_tag(name:"summary", value:"A Telnet Server is running at this host.

  Experts in computer security, such as SANS Institute, and the members of the
  comp.os.linux.security newsgroup recommend that the use of Telnet for remote
  logins should be discontinued under all normal circumstances, for the following
  reasons:

  * Telnet, by default, does not encrypt any data sent over the connection
  (including passwords), and so it is often practical to eavesdrop on the
  communications and use the password later for malicious purposes. Anybody who
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

port = get_all_tcp_ports();

# nb: We still want to collect / report the data below for
# services detected as telnet by find_service.nasl...
if( ! verify_service( port:port, proto:"telnet" ) &&
    ! service_is_unknown( port:port ) ) {
  exit( 0 );
}

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

# nb: Don't use get_telnet_banner() as we want to use telnet_verify_banner()
# without the need to have dump.inc and misc_func.inc included in every VT
# using get_telnet_banner().
banner = telnet_negotiate( socket:soc );
if( ! telnet_verify_banner( data:banner ) ) {
  close( soc );
  exit( 0 );
}

telnet_close_socket( socket:soc, data:banner );

if( "login:" >!< tolower( banner ) )
  set_kb_item( name:"telnet/" + port + "/no_login_banner", value:TRUE ); # for check_account()

register_service( port:port, proto:"telnet", message:"A Telnet server seems to be running on this port" );
telnet_set_banner( port:port, banner:banner );
set_kb_item( name:"telnet/banner/available", value:TRUE );

log_message( port:port, data:"A Telnet server seems to be running on this port" );

exit( 0 );