# OpenVAS Vulnerability Test
# $Id: avirt_gateway_telnet.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Avirt gateway insecure telnet proxy
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

tag_summary = "It was possible to connect to the remote telnet server without
password and to get a command prompt with the 'DOS' command.

An attacker may use this flaw to get access on your system.";

tag_solution = "Contact your vendor for a patch or disable this service";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11096");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3901);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-0134");
 name = "Avirt gateway insecure telnet proxy";
 script_name(name);
 

	 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_require_ports("Services/telnet", 23);
 script_dependencies("find_service.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;
if (!get_port_state(port))  exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = telnet_negotiate(socket:soc);
cmd = string("dos\r\n");
send(socket:soc, data:cmd);
res = recv(socket: soc, length: 512);

close(soc);
flag = egrep(pattern:"^[A-Z]:\\.*>", string: res);
if (flag) security_message(port);
