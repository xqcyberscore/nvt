###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln01_mar14_macosx.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Wireshark 'M3UA' Denial of Service Vulnerability-01 Mar14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:wireshark:wireshark";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804334";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-2282");
  script_bugtraq_id(66070);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-14 11:40:29 +0530 (Fri, 14 Mar 2014)");
  script_name("Wireshark 'M3UA' Denial of Service Vulnerability-01 Mar14 (Mac OS X)");

  tag_summary =
"This host is installed with Wireshark and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper memory allocation by 'dissect_protocol_data_parameter'
function within the M3UA dissector (epan/dissectors/packet-m3ua.c).";

  tag_impact =
"Successful exploitation will allow attackers to cause a Denial of Service.

Impact Level: Application";

  tag_affected =
"Wireshark version 1.10.x before 1.10.6 on Mac OS X";

  tag_solution =
"Upgrade to Wireshark version 1.10.6 or later,
For updates refer to http://www.wireshark.org/download";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57265");
  script_xref(name : "URL" , value : "https://www.wireshark.org/security/wnpa-sec-2014-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
sharkVer = "";

## Get version
if(!sharkVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# Check for vulnerable version
if(sharkVer  =~ "^(1\.10)")
{
  if(version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.5"))
  {
    security_message(0);
    exit(0);
  }
}
