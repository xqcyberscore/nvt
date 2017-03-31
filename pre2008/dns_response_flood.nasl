###############################################################################
# OpenVAS Vulnerability Test
# $Id: dns_response_flood.nasl 4463 2016-11-10 08:01:39Z cfi $
#
# Multiple Vendor DNS Response Flooding Denial Of Service
#
# Authors:
# Cedric Tissieres <cedric dot tissieres at objectif-securite dot ch>
# Modified by Tenable Network Security to slightly change the way the
# query is performed and the vulnerability is detected.
#
# Copyright:
# Copyright (C) 2004 Cedric Tissieres, Objectif Securite
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

# Multiple Vendor DNS Response Flooding Denial Of Service
# NISCC Vulnerability Advisory 758884/NISCC/DNS
# http://www.uniras.gov.uk/vuls/2004/758884/index.htm

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15753");
  script_version("$Revision: 4463 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-10 09:01:39 +0100 (Thu, 10 Nov 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(11642);
  script_cve_id("CVE-2004-0789");
  script_name("Multiple Vendor DNS Response Flooding Denial Of Service");
  script_category(ACT_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2004 Cedric Tissieres, Objectif Securite");
  script_mandatory_keys("DNS/identified");
  script_dependencies("dns_server.nasl");

  tag_summary = "Multiple DNS vendors are reported susceptible to a denial of service
  vulnerability (Axis Communication, dnrd, Don Moore, Posadis).";

  tag_insight = "This vulnerability results in vulnerable DNS servers entering into an infinite
  query and response message loop, leading to the consumption of network and
  CPU resources, and denying DNS service to legitimate users.";

  tag_impact = "An attacker may exploit this flaw by finding two vulnerable servers and
  set up a 'ping-pong' attack between the two hosts.";

  tag_solution = "http://www.uniras.gov.uk/vuls/2004/758884/index.htm";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if ( islocalhost() ) exit( 0 );

port = get_kb_item( "Services/udp/domain" );
if ( ! port ) port = 53;

if( ! get_udp_port_state( port ) ) exit( 0 );

soc = open_sock_udp ( port );
if ( ! soc ) exit( 0 );

my_data  = string( "\xf2\xe7\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77" );
my_data += string( "\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00" );
my_data += string( "\x00\x01\x00\x01" );

send( socket:soc, data:my_data );
r = recv( socket:soc, length:4096 );

if( r && ( ord(r[2]) & 0x80 ) ) {

  send( socket:soc, data:r );
  r = recv( socket:soc, length:4096 );

  if( r && ( ord(r[2]) & 0x80 ) ) {
    security_message( port:port, proto:"udp" );
    exit( 0 );
  }
}

exit( 99 );
