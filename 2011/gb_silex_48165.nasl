###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_silex_48165.nasl 3104 2016-04-18 14:53:56Z benallard $
#
# Silex 'sitemap.php' Cross Site Scripting Vulnerability
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

tag_summary = "Silex is prone to a cross-site scripting vulnerability because it
fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Silex 1.5.4.2 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103180);
 script_version("$Revision: 3104 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-18 16:53:56 +0200 (Mon, 18 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-06-09 13:50:22 +0200 (Thu, 09 Jun 2011)");
 script_bugtraq_id(48165);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_name("Silex 'sitemap.php' Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48165");
 script_xref(name : "URL" , value : "http://projects.silexlabs.org/?/silex/#/flash.cms/what.is.silex");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if Silex is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/silex","/cms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/sitemap.php?id_site=<script>alert(/openvas-xss-test/)</script>"); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",extra_check:"feed.php",check_header:TRUE)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

