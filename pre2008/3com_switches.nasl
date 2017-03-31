###############################################################################
# OpenVAS Vulnerability Test
# $Id: 3com_switches.nasl 4903 2017-01-02 12:13:57Z cfi $
#
# 3Com Superstack 3 switch with default password
#
# Authors:
# Patrik Karlsson <patrik.karlsson@ixsecurity.com>
# Enhancements by Tomi Hanninen
#
# Copyright:
# Copyright (C) 2001 Patrik Karlsson
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
  script_oid("1.3.6.1.4.1.25623.1.0.10747");
  script_version("$Revision: 4903 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 13:13:57 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("3Com Superstack 3 switch with default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Patrik Karlsson");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports(23); # the port can't be changed on the device

  script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value: "no");
 
  tag_summary = "The 3Com Superstack 3 switch has the default passwords set.";

  tag_impact = "The attacker could use these default passwords to gain remote
  access to your switch and then reconfigure the switch. These passwords could
  also be potentially used to gain sensitive information about your network from the switch.";

  tag_solution = "Telnet to this switch and change the default passwords
  immediately.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");
include("default_credentials.inc");

port = 23; # the port can't be changed on the device

banner = get_telnet_banner( port:port );
if( "Login : " >!< banner ) exit( 0 );

found = FALSE;

report = string( "Standard passwords were found on this 3Com Superstack switch.\n" );
report += string( "The passwords found are:\n\n" );

if( get_port_state( port ) ) {

  p = script_get_preference( "Use complete password list (not only vendor specific passwords)" );

  if( "yes" >< p ) {
    clist = try();
  } else {
    clist = try( vendor:"3com" );
  }

  foreach credential( clist ) {

    user_pass = split( credential, sep:";", keep:FALSE );
    if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) continue;

    user = chomp( user_pass[0] );
    pass = chomp( user_pass[1] );

    if( tolower( pass ) == "none" ) pass = "";

    soc = open_sock_tcp( port );
    if( ! soc ) continue;

    r = recv( socket:soc, length:160 );
    if( "Login: " >< r ) {
      tmp = string( user, "\r\n" );
      send( socket:soc, data:tmp );
      r = recv_line( socket:soc, length:2048 );
      tmp = string( pass, "\r\n" );
      send( socket:soc, data:tmp );
      r = recv( socket:soc, length:4096 );

      if( "logout" >< r ) {
        found = TRUE;
        report += string( user, ":", pass, "\n" );
      }
    }
    close( soc );
  }
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );