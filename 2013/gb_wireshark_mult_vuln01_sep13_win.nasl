###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln01_sep13_win.nasl 31865 2013-09-26 19:35:17Z sep$
#
# Wireshark Multiple Vulnerabilities-01 Sep13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:wireshark:wireshark";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804016";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_cve_id("CVE-2013-5718", "CVE-2013-5719", "CVE-2013-5720", "CVE-2013-5721",
                "CVE-2013-5722");
  script_bugtraq_id(62315, 62318, 62319, 62320, 62321);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-09-26 19:35:17 +0530 (Thu, 26 Sep 2013)");
  script_name("Wireshark Multiple Vulnerabilities-01 Sep13 (Windows)");

  tag_summary =
"This host is installed with Wireshark and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to error in,
- ASSA R3 dissector (dissectors/packet-assa_r3.c)
- NBAP dissector (dissectors/packet-nbap.c)
- RTPS dissector (dissectors/packet-rtsp.c)
- LDAP dissector (dissectors/packet-ldap.c)
- MQ dissector (dissectors/packet-mq.c)
- Netmon file parser (wiretap/netmon.c)";

  tag_impact =
"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
and potentially compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Wireshark 1.8.x before 1.8.10 and 1.10.x before 1.10.2 on Windows";

  tag_solution =
"Upgrade to Wireshark version 1.8.10 or 1.10.2 or later,
For updates refer to http://www.wireshark.org/download";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54765");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
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
if(sharkVer  =~ "^(1\.(8|10))")
{
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.9")||
     version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.1"))
  {
    security_message(0);
    exit(0);
  }
}
