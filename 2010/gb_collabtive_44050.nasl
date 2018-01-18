###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabtive_44050.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Collabtive Cross Site Scripting and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Collabtive is prone to multiple cross-site scripting vulnerabilities
and an HTML-injection vulnerability because it fails to properly
sanitize user-supplied input before using it in dynamically
generated content.

Successful exploits will allow attacker-supplied HTML and script
code to run in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials or to control how the site is rendered to the user.
Other attacks are also possible.

Collabtive 0.65 is vulnerable; prior versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100855");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-13 18:51:23 +0200 (Wed, 13 Oct 2010)");
 script_cve_id("CVE-2010-5284","CVE-2010-5285");
 script_bugtraq_id(44050);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("Collabtive Cross Site Scripting and HTML Injection Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44050");
 script_xref(name : "URL" , value : "http://www.collabtive.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_collabtive_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"collabtive"))exit(0);

url = string(dir, "/thumb.php?pic=%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE,extra_check:"file=")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
