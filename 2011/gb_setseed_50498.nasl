###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_setseed_50498.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# SetSeed 'loggedInUser' SQL Injection Vulnerability
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

tag_summary = "SetSeed is prone to an SQL Injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an
SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database implementation.

SetSeed 5.8.20 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103327");
 script_bugtraq_id(50498);
 script_version ("$Revision: 9351 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("SetSeed 'loggedInUser' SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50498");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5053.php");
 script_xref(name : "URL" , value : "http://setseed.com/");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-11-03 08:00:00 +0100 (Thu, 03 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_active");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_setseed_detect.nasl");
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

if(! dir = get_dir_from_kb(port:port, app: "SetSeed"))exit(0);

url = string(dir, "/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);",string:buf);
if(isnull(session_id[1]))exit(0);
sess = session_id[1];

host = get_host_name();

req = string(
              "GET /setseed-hub/ HTTP/1.1\r\n",
              "Cookie: loggedInKey=PYNS9QVWLEBG1E7C9UFCT674DYNW9YJ; loggedInUser=1%27; ",sess,"\r\n",
              "Host: ",host,"\r\n",
              "Connection: Keep-alive\r\n",
              "\r\n\r\n"
             );

res = http_keepalive_send_recv(port:port,data:req);

if("You have an error in your SQL syntax" >< res) {

  security_message(port:port);
  exit(0);

}

exit(0);
