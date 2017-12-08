# OpenVAS Vulnerability Test
# $Id: poppassd_too_long_user.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: poppassd USER overflow
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

tag_summary = "The remote poppassd daemon crashes when a too 
long name is sent after the USER command.

It might be possible for a remote cracker to run 
arbitrary code on this machine.";

tag_solution = "upgrade your software or use another one";

if(description)
{
 script_id(17295);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-1999-1113");
 script_bugtraq_id(75);

 name = "poppassd USER overflow";
 
 script_name(name);
 

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);

 script_require_ports(106, "Services/pop3pw");
 script_dependencies('find_service1.nasl', 'find_service_3digits.nasl');
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

port = get_kb_item("Services/pop3pw");
if (! port) port = 106;

if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

r = recv_line(socket:soc, length:4096);
if (r !~ '^200 ') exit (0);

send(socket: soc, data: 'USER openvas\r\n');
r = recv_line(socket: soc, length: 4096);
if (r !~ '^200 ') exit (0);

send(socket: soc, data: 'PASS '+crap(4096)+'\r\n');
line = recv_line(socket: soc, length: 4096);
close(soc);

sleep(1);

soc = open_sock_tcp(port);
if (! soc) { security_message(port); exit(0); }

if (! line)
security_message(port: port, data: "
The remote poppassd daemon abruptly closes the connection
when it receives a too long USER command.

It might be vulnerable to an exploitable buffer overflow; 
so a cracker might run arbitrary code on this machine.

*** Note that OpenVAS did not crash the service, so this
*** might be a false positive.
*** However, if the poppassd service is run through inetd
*** it is impossible to reliably test this kind of flaw.

Solution: upgrade your software or use another one");
