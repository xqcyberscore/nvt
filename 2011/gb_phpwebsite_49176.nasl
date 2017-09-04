###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpwebsite_49176.nasl 7015 2017-08-28 11:51:24Z teissa $
#
# phpWebSite 'page_id' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.103212");
 script_version("$Revision: 7015 $");
 script_tag(name:"last_modification", value:"$Date: 2017-08-28 13:51:24 +0200 (Mon, 28 Aug 2017) $");
 script_tag(name:"creation_date", value:"2011-08-18 15:52:07 +0200 (Thu, 18 Aug 2011)");
 script_bugtraq_id(49176);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("phpWebSite 'page_id' Parameter Cross Site Scripting Vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_phpWebSite_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49176");
 script_xref(name:"URL", value:"http://phpwebsite.appstate.edu/");

 script_tag(name:"summary", value:"phpWebSite is prone to a cross-site scripting vulnerability because it
 fails to properly sanitize user-supplied input.");
 script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
 in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
 to steal cookie-based authentication credentials and to launch other attacks.");

 script_tag(name:"qod_type", value:"remote_app");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

if( ! dir = get_dir_from_kb( port:port, app:"phpWebSite" ) ) exit( 0 );

url = dir + "/mod.php?mod=userpage&page_id=1<script>alert(/openvas-xss-test/)</script>";

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
