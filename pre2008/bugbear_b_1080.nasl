# OpenVAS Vulnerability Test
# $Id: bugbear_b_1080.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Bugbear.B worm
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2003 Tenable Network Security
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

tag_summary = "BugBear.B backdoor is listening on this port. 
A cracker may connect to it to retrieve secret 
information, e.g. passwords or credit card numbers...

The BugBear.B worm includes a key logger and can kill 
antivirus or personal firewall softwares. It propagates 
itself through email and open Windows shares.";

tag_solution = "- Use an Anti-Virus package to remove it.
- Close your Windows shares
- See http://www.symantec.com/avcenter/venc/data/w32.bugbear.b@mm.removal.tool.html";

if(description)
{
 script_id(11733);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 name = "Bugbear.B worm";

 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2003 Tenable Network Security");
 family = "Malware";
 script_family(family);
 script_require_ports(1080);
 script_dependencies("find_service.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include("misc_func.inc");


#
# bugbear.b is bound to port 1080. It sends data which seems to
# be host-specific when it receives the letter "p"
#
port = 1080;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
send(socket:soc, data:"p");
r = recv(socket: soc, length: 308);
close(soc);
if(!strlen(r))exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, data: "x");
r2 = recv(socket: soc, length: 308);
if(strlen(r2)) { exit(0); }
close(soc);


if(strlen(r) > 10 )
{
 security_message(port); 
 register_service(port: port, proto: "bugbear_b");
 exit(0); 
}
