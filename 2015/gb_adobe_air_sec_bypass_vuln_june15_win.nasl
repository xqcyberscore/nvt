###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_sec_bypass_vuln_june15_win.nasl 8176 2017-12-19 12:50:00Z cfischer $
#
# Adobe Air Security Bypass Vulnerability - June15 (Windows)
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

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805590");
  script_version("$Revision: 8176 $");
  script_cve_id("CVE-2015-3097");
  script_bugtraq_id(75090);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:50:00 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-06-15 13:30:22 +0530 (Mon, 15 Jun 2015)");
  script_name("Adobe Air Security Bypass Vulnerability - June15 (Windows)");

  script_tag(name: "summary" , value: "This host is installed with Adobe Air and
  and is prone to security bypass vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The error exists due to improper selection
  of a random memory address for the Flash heap.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and execute arbitrary code on
  affected system.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Air versions before 18.0.0.180 on
  Windows.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Air version 18.0.0.180
  or later. For updates refer to http://get.adobe.com/air");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://helpx.adobe.com/security/products/flash-player/apsb15-16.html");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

## Variable Initialization
airVer = "";

## Check for Win-7 64-bit OS, only Win-7 64-bit OS is affected
if(hotfix_check_sp(win7x64:2) <= 0){
  exit(0);
}

## Get version
if(!airVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:airVer, test_version:"18.0.0.180"))
{
  report = 'Installed version: ' + airVer + '\n' +
           'Fixed version:     ' + "18.0.0.180" + '\n';
  security_message(data:report);
  exit(0);
}
