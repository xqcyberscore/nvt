###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firestats_41548.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# FireStats Multiple Cross Site Scripting Vulnerabilities
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

tag_summary = "FireStats is prone to multiple cross-site scripting vulnerabilities
because it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100710");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)");
 script_bugtraq_id(41548);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("FireStats Multiple Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41548");
 script_xref(name : "URL" , value : "http://firestats.cc/");
 script_xref(name : "URL" , value : "http://firestats.cc/");
 script_xref(name : "URL" , value : "http://firestats.cc/ticket/1358#comment:3");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("firestats_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"FireStats"))exit(0);

url = string(dir,"/php/window-add-excluded-ip.php?edit=%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E"); 

if(http_vuln_check(port:port,url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

