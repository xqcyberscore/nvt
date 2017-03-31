###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_w_cms_51359.nasl 3058 2016-04-14 10:45:44Z benallard $
#
# w-CMS HTML Injection and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "w-CMS is prone to multiple HTML-injection vulnerabilities and a local
file-include vulnerability.

Exploiting these issues could allow an attacker to execute arbitrary
HTML and script code in the context of the affected browser, steal
cookie-based authentication credentials, and execute arbitrary local
scripts in the context of the webserver process. Other attacks are
also possible.

w-CMS 2.0.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103384);
 script_bugtraq_id(51359);
 script_version ("$Revision: 3058 $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("w-CMS HTML Injection and Local File Include Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51359");
 script_xref(name : "URL" , value : "http://w-cms.info/");

 script_tag(name:"last_modification", value:"$Date: 2016-04-14 12:45:44 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-01-11 11:29:25 +0100 (Wed, 11 Jan 2012)");
 script_summary("Determine if installed w-CMS is vulnerable");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

dirs = make_list("/cms","/w-cms","/w_cms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/?p=<script>alert(/openvas-xss-test/)</script>"); 

  if(http_vuln_check(port:port,url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE,extra_check:"Powered by.*w-CMS")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
