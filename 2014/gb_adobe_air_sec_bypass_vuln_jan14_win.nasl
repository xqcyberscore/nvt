###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_sec_bypass_vuln_jan14_win.nasl 34612 2014-01-21 11:17:57Z Jan$
#
# Adobe AIR Security Bypass Vulnerability Jan14 (Windows)
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

CPE = "cpe:/a:adobe:adobe_air";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804066";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8176 $");
  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_bugtraq_id(64807, 64810);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:50:00 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-01-21 11:17:57 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe AIR Security Bypass Vulnerability Jan14 (Windows)");

  tag_summary =
"This host is installed with Adobe AIR and is prone to security bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an unspecified error and other additional weakness.";

  tag_impact =
"Successful exploitation will allow attackers to, bypass certain security
restrictions and disclose certain memory informations.

Impact Level: System/Application";

  tag_affected =
"Adobe AIR version before 4.0.0.1390 on Windows.";

  tag_solution =
"Update to Adobe AIR version 4.0.0.1390 or later,
For updates refer to  http://get.adobe.com/air";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56267");
  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/flash-player/apsb14-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
airVer = "";

## Get version
if(!airVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:airVer, test_version:"4.0.0.1390"))
{
  security_message(0);
  exit(0);
}
