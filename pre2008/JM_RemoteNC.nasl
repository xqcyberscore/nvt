###############################################################################
# OpenVAS Vulnerability Test
# $Id: JM_RemoteNC.nasl 4817 2016-12-20 15:32:25Z cfi $
#
# RemoteNC detection
#
# Authors:
# Joseph Mlodzianowski <joseph@rapter.net>
# thanks to H.D.Moore
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-07-06
# Removed the CVSS Base and Risk Factor
#
# Copyright:
# Copyright (C) 2003 J.Mlodzianowski
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
  script_oid("1.3.6.1.4.1.25623.1.0.11855");
  script_version("$Revision: 4817 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-20 16:32:25 +0100 (Tue, 20 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RemoteNC detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 J.Mlodzianowski");
  script_family("Malware");
  script_dependencies("find_service2.nasl", "JM_FsSniffer.nasl");
  script_require_ports("Services/RemoteNC", 19340);

  tag_summary = "This host appears to be running RemoteNC on this port

  RemoteNC is a Backdoor which allows an intruder gain
  remote control of your computer.";

  tag_impact = "An attacker may use it to steal your passwords.";

  tag_solution = "See www.rapter.net/jm2.htm for details on removal";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/RemoteNC");
if( ! port ) port = 19340;

if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

r = recv( socket:soc, min:1, length:30 );
close( soc );
if( ! r ) exit( 0 );

if( "RemoteNC Control Password:" >< r ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
