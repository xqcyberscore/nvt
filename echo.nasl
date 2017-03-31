###############################################################################
# OpenVAS Vulnerability Test
# $Id: echo.nasl 4378 2016-10-28 09:01:50Z cfi $
#
# Check for echo Service
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100075");
  script_version("$Revision: 4378 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-28 11:01:50 +0200 (Fri, 28 Oct 2016) $");
  script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #script_cve_id("CVE-1999-0635");
  script_name("Check for echo Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/echo", 7);

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0635");

  tag_summary = "Echo Service is running at this Host.

  The echo service is an Internet protocol defined in RFC 862. It was
  originally proposed for testing and measurement of round-trip times in IP
  networks. While still available on most UNIX-like operating systems, testing
  and measurement is now performed with the Internet Control Message Protocol
  (ICMP), using the applications ping and traceroute.";

  tag_solution = "Disable echo Service.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item( "Services/echo" );
if( ! port ) port = 7;

echo_string = string( "OpenVAS-Echo-Test" );

if( get_port_state( port ) ) {

  soc = open_sock_tcp( port );
  if( soc ) {

    send( socket:soc, data:echo_string );
    buf = recv( socket:soc, length:4096 );
    close( soc );

    if( buf == echo_string ) {
      register_service( port:port, proto:"echo", ipproto:"tcp" );
      security_message( port:port, protocol:"tcp" );
    }
  }
}

if( get_udp_port_state( port ) ) {

  soc = open_sock_udp( port );
  if( soc ) {

    send( socket:soc, data:echo_string );
    buf = recv( socket:soc, length:4096 );
    close( soc );
    if( buf == echo_string ) {
      register_service( port:port, proto:"echo", ipproto:"udp" );
      security_message( port:port, protocol:"udp" );
    }
  }
}

exit( 0 );
