###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_ecommerce_49264.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Axis Commerce HTML Injection Vulnerability
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

tag_summary = "Axis Commerce is prone to an HTML-injection vulnerability because it
fails to sufficiently sanitize user-supplied data.

Attacker-supplied HTML and script code would run in the context of the
affected browser, potentially allowing the attacker to steal cookie-
based authentication credentials or control how the site is rendered
to the user. Other attacks are also possible.

Axis Commerce versions 0.8.1 and prior are vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103224");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-24 15:44:33 +0200 (Wed, 24 Aug 2011)");
 script_bugtraq_id(49264);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Axis Commerce HTML Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49264");
 script_xref(name : "URL" , value : "https://github.com/downloads/axis/axiscommerce/axis-0.8.1.zip");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_axis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if( ! dir = get_dir_from_kb(port:port,app:"axis_ecommerce"))exit(0);

url = string(dir, "/search/result?q=%22%3E%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE)) {
     
  security_message(port:port);
  exit(0);

}

exit(0);
