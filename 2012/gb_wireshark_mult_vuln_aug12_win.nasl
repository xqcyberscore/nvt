###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_aug12_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Wireshark Multiple Vulnerabilities - August 2012 (Windows)
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

tag_impact = "Successful exploitation will allow remote attackers to denial of service or
  to consume excessive CPU resources.
  Impact Level: Application";
tag_affected = "Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10,
  and 1.8.x before 1.8.2 on Windows";
tag_insight = "The flaws are due to
  - A division by zero error within the DCP ETSI dissector, an error within
    the STUN dissector and EtherCAT Mailbox dissector can be exploited to
    cause a crash.
  - An error within the RTPS2 dissector can be exploited to cause a buffer
    overflow.
  - An error within the STUN dissector can be exploited to cause a crash.
  - An error within the CIP dissector can be exploited to exhaust memory.
  - An error within the CTDB dissector, AFP dissector and XTP dissector can be
    exploited to trigger an infinite loop and consume excessive CPU resources.";
tag_solution = "Upgrade to the Wireshark version 1.4.15, 1.6.10 or 1.8.2 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802944");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-4285", "CVE-2012-4296", "CVE-2012-4293", "CVE-2012-4292",
                "CVE-2012-4291", "CVE-2012-4290", "CVE-2012-4289", "CVE-2012-4288");
  script_bugtraq_id(55035);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-21 13:48:05 +0530 (Tue, 21 Aug 2012)");
  script_name("Wireshark Multiple Vulnerabilities - August 2012 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50276/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027404");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-13.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-20.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-23.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-17.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-15.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range(version:sharkVer, test_version:"1.4.0", test_version2:"1.4.14") ||
   version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.9") ||
   version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.1")) {
  security_message(0);
}
