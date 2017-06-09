###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sea_monkey_mult_vuln01_dec13_win.nasl 33846 2013-12-23 18:34:28Z dec$
#
# SeaMonkey Multiple Vulnerabilities-01 Dec13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:seamonkey";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804045";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5612", "CVE-2013-5613",
                "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618",
                "CVE-2013-5619", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673");
  script_bugtraq_id(64204, 64206, 64205, 64203, 64207, 64216,
                    64209, 64211, 64215, 64212, 64210, 64213);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-23 18:34:28 +0530 (Mon, 23 Dec 2013)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 Dec13 (Windows)");

  tag_summary =
"This host is installed with SeaMonkey and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"For more details about the vulnerabilities, refer the reference section.";

  tag_impact =
"Successful exploitation will allow attackers to conduct cross-site scripting
attacks, bypass certain security restrictions, disclose potentially sensitive
information, and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"SeaMonkey version before 2.23 on Windows";

  tag_solution =
"Upgrade to SeaMonkey version 2.23 or later,
For updates refer to http://www.mozilla.com/en-US/seamonkey";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56002");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
smVer = "";

## Get version
if(!smVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# Check for vulnerable version
if(version_is_less(version:smVer, test_version:"2.23"))
{
  security_message(0);
  exit(0);
}
