###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_mar13_macosx.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Wireshark Multiple Dissector Multiple DoS Vulnerabilities - March 13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to cause denial of
  service or to consume excessive CPU resources.
  Impact Level: Application";

tag_affected = "Wireshark 1.6.x before 1.6.14, 1.8.x before 1.8.6 on Mac OS X";
tag_insight = "Multiple flaws are due to errors in MS-MMS, RTPS, RTPS2, Mount, AMPQ, ACN,
  CIMD, FCSP and DTLS dissectors.";
tag_solution = "Upgrade to the Wireshark version 1.6.14 or 1.8.6 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803332");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2478", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482",
                "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2488");
  script_bugtraq_id(58357, 58351, 58340, 58353, 58355, 58356, 58362, 58365);
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-11 19:20:06 +0530 (Mon, 11 Mar 2013)");
  script_name("Wireshark Multiple Dissector Multiple DoS Vulnerabilities - March 13 (Mac OS X)");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52471");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028254");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/MacOSX/Version");

if(sharkVer && sharkVer=~ "^(1.6|1.8)")
{
  ## Check for vulnerable Wireshark versions
  if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.11") ||
     version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.3")){
    security_message(0);
    exit(0);
  }
}
