# OpenVAS Vulnerability Test
# $Id: finger_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: fingerd buffer overflow
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
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

tag_summary = "OpenVAS was able to crash the remote finger daemon by sending a too long 
request. 

This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine.";

tag_solution = "Disable your finger daemon, apply the latest patches from your
vendor, or a safer software.";

if(description)
{
 script_id(17141);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_bugtraq_id(2);
 name = "fingerd buffer overflow";
 
 script_name(name);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");

 family = "Finger abuses";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/finger", 79);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include('global_settings.inc');

port = get_kb_item("Services/finger");
if(!port) port = 79;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

send(socket: soc, data: crap(4096)+ '\r\n');
r = recv(socket:soc, length:65535);

close(soc);

sleep(1);

soc = open_sock_tcp(port);
if(! soc) { security_message(port); exit(0); }
else close(soc);

if (! r)
security_message(port: port, data:
"The remote finger daemon abruptly closes the connection
when it receives a too long request.
It might be vulnerable to an exploitable buffer overflow; 
so a cracker might run arbitrary code on this machine.

*** Note that OpenVAS did not crash the service, so this
*** might be a false positive.
*** However, if the finger service is run through inetd
*** (a very common configuration), it is impossible to 
*** reliably test this kind of flaw.

Solution: Disable your finger daemon,
	 apply the latest patches from your vendor,
	 or a safer software.");
