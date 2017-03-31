###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyfaq_43560.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# phpMyFAQ 'index.php' Cross Site Scripting Vulnerability
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

tag_summary = "phpMyFAQ is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

Versions prior to phpMyFAQ 2.6.9 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100829);
 script_version("$Revision: 5373 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-09-29 12:56:18 +0200 (Wed, 29 Sep 2010)");
 script_bugtraq_id(43560);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("phpMyFAQ 'index.php' Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43560");
 script_xref(name : "URL" , value : "http://www.phpmyfaq.de/advisory_2010-09-28.php");
 script_xref(name : "URL" , value : "http://www.phpmyfaq.de/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"phpmyfaq"))exit(0);

url = string(dir, "/index.php/%22%3E%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E"); 

if(http_vuln_check(port:port,url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",bodyonly:TRUE,check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

