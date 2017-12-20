###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_mult_vuln01_oct14_win.nasl 8178 2017-12-19 13:42:38Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities(APSB14-22)-(Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805002");
  script_version("$Revision: 8178 $");
  script_cve_id("CVE-2014-0558", "CVE-2014-0564", "CVE-2014-0569", "CVE-2014-8439");
  script_bugtraq_id(70437, 70442, 70441, 71289);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 14:42:38 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-10-20 12:31:59 +0530 (Mon, 20 Oct 2014)");

  script_name("Adobe Flash Player Multiple Vulnerabilities(APSB14-22)-(Windows)");

  script_tag(name: "summary" , value:"This host is installed with Adobe Flash
  Player and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple Flaws are due to,
  - Two unspecified errors can be exploited to corrupt memory and subsequently
    execute arbitrary code.
  - An integer overflow error can be exploited to execute arbitrary code.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to execute arbitrary code and compromise a user's system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Flash Player version before
  13.0.0.250 and 14.x and 15.x before 15.0.0.189 on Windows");

  script_tag(name: "solution" , value:"Upgrade to Adobe Flash Player version
  13.0.0.250 or 15.0.0.189 or later. For updates refer to
  http://get.adobe.com/flashplayer");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59729");
  script_xref(name : "URL" , value : "http://helpx.adobe.com/security/products/flash-player/apsb14-22.html");
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
if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:playerVer, test_version:"13.0.0.250") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"15.0.0.188"))
{
  security_message(0);
  exit(0);
}
