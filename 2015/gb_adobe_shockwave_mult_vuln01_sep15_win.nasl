###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_mult_vuln01_sep15_win.nasl 6254 2017-05-31 09:04:18Z teissa $
#
# Adobe Shockwave Player Multiple Vulnerabilities -01 Sep15 (Windows)
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

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805980");
  script_version("$Revision: 6254 $");
  script_cve_id("CVE-2015-6680", "CVE-2015-6681");
  script_bugtraq_id(76664);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-31 11:04:18 +0200 (Wed, 31 May 2017) $");
  script_tag(name:"creation_date", value:"2015-09-14 10:49:07 +0530 (Mon, 14 Sep 2015)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities -01 Sep15 (Windows)");

  script_tag(name: "summary" , value: "This host is installed with Adobe Shockwave
  Player and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "Multiple flaws are due to multiple memory
  corruption errors.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack and potentially execute arbitrary
  code in the context of the affected user.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Shockwave Player version before
  12.2.0.162 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Shockwave Player version
  12.2.0.162 or later. For updates refer to http://get.adobe.com/shockwave");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://helpx.adobe.com/security/products/shockwave/apsb15-22.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
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
if(version_is_less(version:playerVer, test_version:"12.2.0.162"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "12.2.0.162" + '\n';
  security_message(data:report);
  exit(0);
}
