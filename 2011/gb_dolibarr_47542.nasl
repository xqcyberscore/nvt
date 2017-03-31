###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_47542.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Dolibarr Local File Include and Cross Site Scripting Vulnerabilities
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

tag_summary = "Dolibarr is prone to a local file-include vulnerability and a cross-
site scripting vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerability using
directory-traversal strings to view and execute local files within
the context of the affected application. Information harvested may
aid in further attacks.

The attacker may leverage the cross-site scripting issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

Dolibarr 3.0.0 is vulnerable; other versions may also be affected.

Reference
https://www.securityfocus.com/bid/47542
http://www.dolibarr.org/downloads/cat_view/62-stables-versions
http://www.dolibarr.org/";


if (description)
{
 script_id(103144);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
 script_bugtraq_id(47542);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_name("Dolibarr Local File Include and Cross Site Scripting Vulnerabilities");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed Dolibarr is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_dolibarr_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"dolibarr"))exit(0);

url = string(dir,"/document.php?lang=%22%3E%3Cscript%3Ealert%28%27openvas-xss-test%27%29%3C/script%3E"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
