###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpadsnew_xss.nasl 10111 2018-06-07 09:30:55Z cfischer $
#
# phpAdsNew Multiple Vulnerabilities
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# phpAdsNew 2.0.4-pr1 Multiple vulnerabilities cXIb8O3.9
# From: Maksymilian Arciemowicz <max@jestsuper.pl>
# Date: 2005-03-15 03:56

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17335");
  script_version("$Revision: 10111 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 11:30:55 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0791");
  script_bugtraq_id(12803);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpAdsNew Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "cross_site_scripting.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"An attacker may use the cross site scripting bug to perform phishing
  attacks.");

  script_tag(name:"summary", value:"phpAdsNew is an open-source ad server, with an integrated banner
  management interface and tracking system for gathering statistics. With phpAdsNew you can easily
  rotate paid banners and your own in-house advertisements. You can even integrate banners from
  third party advertising companies.

  The product has been found to contain two vulnerabilities:

   * Path disclosure vulnerability

   * Cross Site Scripting");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = string( dir, "/adframe.php?refresh=example.com'<script>alert(document.cookie)</script>" );
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( res =~ "HTTP/1\.. 200" && "content='example.com\'><script>alert(document.cookie)</script>'>" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
