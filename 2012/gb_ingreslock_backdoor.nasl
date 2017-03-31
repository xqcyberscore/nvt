###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ingreslock_backdoor.nasl 4718 2016-12-08 13:32:01Z cfi $
#
# Possible Backdoor: Ingreslock
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103549");
  script_version("$Revision: 4718 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-08 14:32:01 +0100 (Thu, 08 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-08-22 16:21:38 +0200 (Wed, 22 Aug 2012)");
  script_name("Possible Backdoor: Ingreslock");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "secpod_open_tcp_ports.nasl");
  script_mandatory_keys("TCP/PORTS");

  tag_summary = "A backdoor is installed on the remote host";

  tag_impact = "Attackers can exploit this issue to execute arbitrary commands in the
  context of the application. Successful attacks will compromise the affected isystem.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");

ports = get_kb_list( "TCP/PORTS" );
if( ! ports ) exit( 0 );

foreach port( ports ) {

  if( ! get_port_state( port ) ) continue;

  soc = open_sock_tcp( port );
  if( ! soc ) continue;

  recv = recv( socket:soc, length:1024 );
  send( socket:soc, data:'id;\r\n\r\n' );
  recv = recv( socket:soc, length:1024 );
  close( soc );

  if( recv =~ "uid=[0-9]+.*gid=[0-9]+" ) {
    security_message( port:port );
  }
}

exit( 99 );
