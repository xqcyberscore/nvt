###############################################################################
# OpenVAS Vulnerability Test
# $Id: pirelli_router_default_password.nasl 4830 2016-12-21 11:48:51Z cfi $
#
# Default password router Pirelli AGE mB
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 1999 Anonymous
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
  script_oid("1.3.6.1.4.1.25623.1.0.12641");
  script_version("$Revision: 4830 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-21 12:48:51 +0100 (Wed, 21 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0502");
  script_name("Default password router Pirelli AGE mB");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 1999 Anonymous");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  tag_summary = "The remote host is a Pirelli AGE mB (microBusiness) router with its 
  default password set (admin/microbusiness).";

  tag_impact = "An attacker could telnet to it and reconfigure it to lock the owner out 
  and to prevent him from using his Internet connection, and do bad things.";

  tag_solution = "Telnet to this router and set a password immediately.";
 
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("default_account.inc");
include("telnet_func.inc");

port = get_telnet_port( default:23 );

banner = get_telnet_banner( port:port );
if( ! banner || "USER:" >!< banner ) exit( 0 );

#First try as Admin
soc = open_sock_tcp( port );
if( soc ) {

  r = recv_until( socket:soc, pattern:"(USER:|ogin:)" );
  if ( "USER:" >!< r ) {
    close( soc );
    exit( 0 );
  }

  s = string( "admin\r\nmicrobusiness\r\n" );
  send( socket:soc, data:s );
  r = recv_until( socket:soc, pattern:"Configuration" );
  close( soc );

  if( r && "Configuration" >< r ) {
    security_message( port:port );
    exit( 0 );
  }
}

#Second try as User (reopen soc beacause wrong pass disconnect)

soc = open_sock_tcp( port );
if( soc ) {

  r = recv_until( socket:soc, pattern:"(USER:|ogin:)" );
  if ( "USER:" >!< r ) {
    close( soc );
    exit( 0 );
  }

  s = string( "user\r\npassword\r\n" );
  send( socket:soc, data:s );
  r = recv_until( socket:soc, pattern:"Configuration" );
  close( soc );

  if( r && "Configuration" >< r ) {
    security_message( port:port );
  }
}

exit( 0 );