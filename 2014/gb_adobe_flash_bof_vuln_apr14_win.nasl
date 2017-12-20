###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_bof_vuln_apr14_win.nasl 8178 2017-12-19 13:42:38Z cfischer $
#
# Adobe Flash Player Buffer Overflow Vulnerability - Apr14 (Windows)
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

CPE = "cpe:/a:adobe:flash_player";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804559";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8178 $");
  script_cve_id("CVE-2014-0515");
  script_bugtraq_id(67092);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 14:42:38 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-29 11:45:09 +0530 (Tue, 29 Apr 2014)");
  script_name("Adobe Flash Player Buffer Overflow Vulnerability - Apr14 (Windows)");

  tag_summary =
"This host is installed with Adobe Flash Player and is prone to buffer
overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an improper validation of user-supplied input to the pixel
bender component.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code and
cause a buffer overflow, resulting in a denial of service condition.

Impact Level: System/Application";

  tag_affected =
"Adobe Flash Player version before 11.7.700.279 and 11.8.x through 13.0.x
before 13.0.0.206 on Windows";

  tag_solution =
"Update to Adobe Flash Player version 11.7.700.279 or 13.0.0.206 or later,
For updates refer to  http://get.adobe.com/flashplayer";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=2577");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/blog/8212");
  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/flash-player/apsb14-13.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get version
if(!playerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:playerVer, test_version:"11.7.700.279") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"13.0.0.205"))
{
  security_message(0);
  exit(0);
}
