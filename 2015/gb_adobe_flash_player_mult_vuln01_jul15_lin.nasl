###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_jul15_lin.nasl 6376 2017-06-20 10:00:24Z teissa $
#
# Adobe Flash Player Multiple Vulnerabilities -01 July15 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805919");
  script_version("$Revision: 6376 $");
  script_cve_id("CVE-2015-5122", "CVE-2015-5123");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-20 12:00:24 +0200 (Tue, 20 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-07-13 10:56:43 +0530 (Mon, 13 Jul 2015)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 July15 (Linux)");

  script_tag(name: "summary" , value: "This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Multiple flaws exist due to,
  - An use-after-free error triggered by freeing a TextLine object within the
  'valueOf' function of a custom class when setting the TextLine's
  opaqueBackground.
  - An unspecified error.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack and potentially execute arbitrary
  code in the context of the affected user.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Flash Player version 11.2.202.481
  and prior on Linux.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Flash Player version
  11.2.202.491 or later. For updates refer to http://get.adobe.com/flashplayer");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name: "URL" , value : "https://helpx.adobe.com/security/products/flash-player/apsa15-04.html");
  script_xref(name: "URL" , value : "https://helpx.adobe.com/security/products/flash-player/apsb15-18.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get version
if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
## Fix will be updated once the solution details are available
if(version_is_less_equal(version:playerVer, test_version:"11.2.202.481"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "11.2.202.491" + '\n';
  security_message(data:report);
  exit(0);
}
