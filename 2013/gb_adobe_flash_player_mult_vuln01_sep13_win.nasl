###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_sep13_win.nasl 8178 2017-12-19 13:42:38Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities-01 Sep13 (Windows)
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

CPE = "cpe:/a:adobe:flash_player";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803897";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8178 $");
  script_cve_id("CVE-2013-5324", "CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363");
  script_bugtraq_id(62296, 62290, 62294, 62295);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 14:42:38 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-09-18 18:33:34 +0530 (Wed, 18 Sep 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 Sep13 (Windows)");

  tag_summary =
"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws are due to multiple unspecified errors.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Adobe Flash Player before 11.7.700.242 and 11.8.x before 11.8.800.168 on
Windows";

  tag_solution =
"Update to Adobe Flash Player version 11.7.700.242 or 11.8.800.168 or later
For updates refer to  http://get.adobe.com/flashplayer";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54697/");
  script_xref(name : "URL" , value : "https://www.adobe.com/support/security/bulletins/apsb13-21.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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
if(version_is_less(version:playerVer, test_version:"11.7.700.242") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"11.8.800.167"))
{
  security_message(0);
  exit(0);
}
