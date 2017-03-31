###############################################################################
# OpenVAS Vulnerability Test
# $Id: psybnc_check.nasl 4909 2017-01-02 13:49:47Z cfi $
#
# psyBNC Server Detection
#
# Authors:
# Scott Shebby
#
# Copyright:
# Copyright (C) 2004 Scott Shebby
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
  script_oid("1.3.6.1.4.1.25623.1.0.14687");
  script_version("$Revision: 4909 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 14:49:47 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("psyBNC Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Scott Shebby");
  script_family("General");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/psyBNC");

  script_xref(name:"URL", value:"http://www.psybnc.info/about.html");
  script_xref(name:"URL", value:"http://www.psychoid.net/start.html");

  tag_summary = "The remote host appears to be running psyBNC on this port.

  psyBNC is an 'easy-to-use, multi-user, permanent IRC-Bouncer with many features. Some 
  of its features include symmetric ciphering of talk and connections (Blowfish and IDEA),
  the possibility of linking multiple bouncers to an internal network including a shared 
  partyline, vhost- and relay support to connected bouncers and an extensive online help 
  system.'";

  tag_impact = "The presence of this service indicates a high possibility that your server has been 
  compromised by a remote attacker. The only sure fix is to reinstall from scratch.";

  tag_solution = "Make sure the presence of this service is intended";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# The detection is in find_service2.nasl
port = get_kb_item( "Services/psyBNC" );
if( port ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );