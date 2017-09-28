###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipmi_zero_cipher.nasl 7287 2017-09-27 06:56:51Z cfischer $
#
# IPMI Cipher Zero Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103840";

tag_insight = "The remote IPMI service accepted a session open request for cipher zero.";

tag_impact = "Attackers can exploit this issue to gain administrative access to the
device and disclose sensitive information.";

tag_summary = "Intelligent Platform Management Interface is prone to an authentication-
bypass vulnerability.";

tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Send a request with a zero cipher and check if this request was accepted.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 7287 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("IPMI Cipher Zero Authentication Bypass Vulnerability");


 script_xref(name:"URL", value:"http://fish2.com/ipmi/cipherzero.html");
 
 script_tag(name:"last_modification", value:"$Date: 2017-09-27 08:56:51 +0200 (Wed, 27 Sep 2017) $");
 script_tag(name:"creation_date", value:"2013-11-27 15:03:17 +0100 (Wed, 27 Nov 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_ipmi_detect.nasl");
 script_require_udp_ports("Services/udp/ipmi", 623);
 script_mandatory_keys("ipmi/version/2.0");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);

 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/udp/ipmi");
if(!port)exit(0);

soc = open_sock_udp(port);
if(!soc)exit(0);

req = raw_string(0x06,0x00,0xff,0x07,0x06,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,
                 0x00,0x00,0x00,0x00,0x71,0x1e,0x24,0x73,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x00,
                 0x01,0x00,0x00,0x08,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x08,0x00,0x00,0x00,0x00);

send(socket:soc, data:req);
recv = recv(socket:soc, length:1024);
close(soc);

if(hexstr(recv) !~ "0600ff07" || strlen(recv) < 16 || hexstr(recv[5]) != "11")exit(0);

len = ord(raw_string(recv[14],recv[15]));
if(len > strlen(recv))exit(0);

data = substr(recv, strlen(recv)-len);

if(data[1]) {  
  if(ord(data[1]) == 0) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

