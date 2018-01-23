###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuralstorm_webmail_41559.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# NuralStorm Webmail Multiple Security Vulnerabilities
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

tag_summary = "NuralStorm Webmail is prone to multiple security vulnerabilities.

An attacker can exploit these vulnerabilities to obtain potentially
sensitive information, create or delete arbitrary files, send
unsolicited bulk email to users, execute arbitrary script code in the
browser of an unsuspecting user in the context of the affected site,
steal cookie-based authentication credentials, perform unauthorized
actions, disclose or modify sensitive information, or upload arbitrary
code and run it in the context of the webserver process. Other attacks
are also possible.

Webmail 0.985b is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100743");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-08-04 13:50:35 +0200 (Wed, 04 Aug 2010)");
 script_bugtraq_id(41559);
 script_name("NuralStorm Webmail Multiple Security Vulnerabilities");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41559");
 script_xref(name : "URL" , value : "http://www.nuralstorm.net/");
 script_xref(name : "URL" , value : "http://www.madirish.net/?article=466");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_nuralstorm_webmail_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port, app:"nuralstorm_webmail")){
   exit(0);
}

url = string(dir, "/book_include.php?USE_ADDRESS_BOOK=1&ADDRESS_BOOK_MESSAGE=1&BGCOLOR1=%22%3E%3Cscript%3Ealert(%27openvas-xss-test%27);%3C/script%3E%3C%22"); 

if(http_vuln_check(port:port,url:url,pattern:"<script>alert\('openvas-xss-test'\);</script>",extra_check:"selectedIndex", check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
