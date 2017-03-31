###############################################################################
# OpenVAS Vulnerability Test
# $Id: JM_Wollf.nasl 4909 2017-01-02 13:49:47Z cfi $
#
# Wollf backdoor detection
#
# Authors:
# Jøséph Mlødzianøwski <joseph@rapter.net>
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-07-06
# Updated the CVSS Base and Risk Factor
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
  script_oid("1.3.6.1.4.1.25623.1.0.11881");
  script_version("$Revision: 4909 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 14:49:47 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Wollf backdoor detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 J.Mlødzianøwski");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/wollf");

  tag_summary = "This host appears to be running Wollf on this port. Wollf Can be used as a 
  Backdoor which allows an intruder gain remote access to files on your computer. 
  If you did not install this program for remote management then this host may 
  be compromised.";

  tag_impact = "An attacker may use it to steal your passwords, or redirect
  ports on your system to launch other attacks";

  tag_solution = "See www.rapter.net/jm4.htm for details on removal";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/wollf" );
if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

