###############################################################################
# OpenVAS Vulnerability Test
# $Id: avaya_switches.nasl 4902 2017-01-02 10:59:52Z cfi $
#
# Avaya P330 Stackable Switch found with default password
#
# Authors:
# Charles Thier <cthier@thethiers.net>
#
# Copyright:
# Copyright (C) 2005 Charles Thier
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
  script_oid("1.3.6.1.4.1.25623.1.0.17638");
  script_version("$Revision: 4902 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 11:59:52 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Avaya P330 Stackable Switch found with default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Charles Thier");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value: "no");

  tag_summary = "The remote host appears to be an Avaya P330 Stackable Switch with its default password set.";

  tag_impact = "The attacker could use this default password to gain remote access
  to your switch. This password could also be potentially used to
  gain other sensitive information about your network from the switch.";

  tag_solution = "Telnet to this switch and change the default password.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("telnet_func.inc");
include("default_credentials.inc");

port = get_telnet_port( default:23 );

banner = get_telnet_banner( port );
if( ! banner || "Welcome to P330" >!< banner ) exit( 0 );

p = script_get_preference( "Use complete password list (not only vendor specific passwords)" );

if( "yes" >< p ) {
  clist = try();
} else {  
  clist = try( vendor:"avaya" );
}   

foreach credential( clist ) {

  user_pass = split( credential, sep:";", keep:FALSE );
  if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) continue;

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  if( tolower( pass ) == "none" ) pass = "";

  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  answer = recv( socket:soc, length:4096 );
  if( "ogin:" >< answer ) {
    send( socket:soc, data:string( user, "\r\n" ) );
    answer = recv( socket:soc, length:4096 );
    send( socket:soc, data:string( pass, "\r\n" ) );
    answer = recv( socket:soc, length:4096 );

    if( "Password accepted" >< answer ) {
      security_message( port:port, data:"It was possible to login with the credentials '" + user + ":" + pass + "'." );
    }
  }
  close( soc );
}

exit( 0 );