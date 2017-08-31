###############################################################################
# OpenVAS Vulnerability Test
# $Id: dwhttp_format_string.nasl 6695 2017-07-12 11:17:53Z cfischer $
#
# dwhttpd format string
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# This script could also cover BID:1556 and CVE-2000-0697
#
# References:
#
# Date:  Thu, 1 Aug 2002 16:31:40 -0600 (MDT)
# From: "ghandi" <ghandi@mindless.com>
# To: bugtraq@securityfocus.com
# Subject: Sun AnswerBook2 format string and other vulnerabilities
#
# Affected:
# dwhttp/4.0.2a7a, dwhttpd/4.1a6
# And others?

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11075");
  script_version("$Revision: 6695 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 13:17:53 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5384);
  script_cve_id("CVE-1999-1417");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("dwhttpd format string");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("dwhttp/banner");
  script_require_ports("Services/www", 8888);

  tag_summary = "The remote web server is vulnerable to a format string attack.";

  tag_impact = "A cracker may exploit this vulnerability to make your web server
  crash continually or even execute arbirtray code on your system.";

  tag_solution = "Upgrade your software or protect it with a filtering reverse proxy";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:8888 );

banner = get_http_banner( port:port );
if( "dwhttp/" >!< banner ) exit( 0 );

if( safe_checks() ) {
  if( egrep( string:banner, pattern:"^Server: *dwhttp/4.(0|1[^0-9])" ) ) {
    security_message( port:port );
  }
  exit( 0 );
}

if( http_is_dead( port:port ) ) exit( 0 );

url = string( "/", crap( data:"%n", length:100 ) );
req = http_get( item:url, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port, retry:2 ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
