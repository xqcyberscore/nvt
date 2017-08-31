###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sea_monkey_mult_vuln01_may14_macosx.nasl 37404 2014-05-06 16:09:49Z may$
#
# SeaMonkey Multiple Vulnerabilities-01 May14 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:mozilla:seamonkey";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804569";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523",
                "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1529",
                "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_bugtraq_id(67123, 67125, 67127, 67129, 67131, 67136,
                    67132, 67135, 67137, 67134, 67130);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-05-06 16:15:38 +0530 (Tue, 06 May 2014)");
  script_name("SeaMonkey Multiple Vulnerabilities-01 May14 (Mac OS X)");

  tag_summary =
"This host is installed with SeaMonkey and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- An error exists when handling Web Audio.
- An error exists when validating the XBL status of an object.
- A use-after-free error exists when processing HTML video in the Text Track
  Manager.
- An error exists when handling site notifications within the Web Notification
  API.
- An error exists when handling browser navigations through history to load a
  website.
- A use-after-free error exists when handling an imgLoader object within the
  'nsGenericHTMLElement::GetWidthHeightForImage()' function.
- An error exists in NSS.
- A use-after-free error exists when handling host resolution within the
  'libxul.so!nsHostResolver::ConditionallyRefreshRecord()' function.
- An error exists when handling the debugging of certain objects.
- And some unspecified errors exist.";

  tag_impact =
"Successful exploitation will allow attackers to conduct spoofing attacks,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"SeaMonkey version before 2.26 on Mac OS X";

  tag_solution =
"Upgrade to SeaMonkey version 2.26 or later,
For updates refer to http://www.mozilla.com/en-US/seamonkey";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58234");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2014/mfsa2014-34.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
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
if(version_is_less(version:smVer, test_version:"2.26"))
{
  security_message(0);
  exit(0);
}
