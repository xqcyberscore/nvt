###############################################################################
# OpenVAS Vulnerability Test
# $Id: JM_urcs.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# URCS Server Detection
#
# Authors:
# J.Mlødzianøwski <jøseph[at]rapter.net>
#
# Copyright:
# Copyright (C) 9/2004 J.Mlodzianowski
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15405");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("URCS Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright(C) 9/2004 J.Mlodzianowski");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 3360);

  script_xref(name:"URL", value:"http://urcs.unmanarc.com");
  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/venc/data/backdoor.urcs.html");

  script_tag(name:"solution", value:"see http://www.rapter.net/jm5.htm");
  script_tag(name:"impact", value:"An attacker may use it to steal files, passwords, or redirect ports on the
  remote system to launch other attacks.");
  script_tag(name:"summary", value:"This host appears to be running URCS Server. Unmanarc Remote Control Server 
  can be used/installed silent as a 'backdoor' which may allow an intruder to gain remote access to files on
  the remote system. If this program was not installed for remote management then it means the remote host has
  been compromised.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("misc_func.inc");

# Default port for URCS Server is 3360
# Default port for URCS Client is 1980
port = get_unknown_port( default:3360 );

soc = open_sock_tcp( port );
if( soc ) {
  send( socket:soc, data:'iux' );
  r = recv( socket:soc, length:817 );
  if( "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" >< r ) {
    security_message( port:port );
    close( soc );
    exit( 0 );
  }
  close( soc );
}

exit( 99 );