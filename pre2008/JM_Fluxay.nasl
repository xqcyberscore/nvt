###############################################################################
# OpenVAS Vulnerability Test
# $Id: JM_Fluxay.nasl 14336 2019-03-19 14:53:10Z mmartin $
#
# Fluxay Sensor Detection
#
# Authors:
# Jøséph Mlødzianøwski <joseph@rapter.net>
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-07-06
# Updated CVSS Base and Risk Factor
#
# Copyright:
# Copyright (C) 2003 J.Mlødzianøwski
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
  script_oid("1.3.6.1.4.1.25623.1.0.11880");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fluxay Sensor Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 J.Mlødzianøwski");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/fluxay");

  script_tag(name:"solution", value:"See www.rapter.net/jm3.htm for details on removal");
  script_tag(name:"summary", value:"This host appears to be running Fluxay Sensor on this port.

  Fluxay Sensor is a Backdoor which allows an intruder gain
  remote access to files on your computer. Similar to SubSeven
  This program is installs as a Service and is password protected.
  It protects itself so it is dificult to stop or remove.");
  script_tag(name:"impact", value:"An attacker may use it to steal your passwords, or use this
  computer in other attacks.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/fluxay" );
if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );