##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_apsa16-02_lin.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# Adobe Flash Player Security Updates( apsa16-02 )-Linux
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808100");
  script_version("$Revision: 7585 $");
  script_cve_id("CVE-2016-4117");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-05-12 15:58:15 +0530 (Thu, 12 May 2016)");
  script_name("Adobe Flash Player Security Updates( apsa16-02 )-Linux");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an unspecified
  vulnerability");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code and
  also some unknown impact.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Flash Player version 20.x through
  21.0.0.240 on Linux.");

  script_tag(name: "solution", value:"Upgrade to Adobe Flash Player version 
  21.0.0.241, or later.
  For updates refer to http://get.adobe.com/flashplayer");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name: "URL" , value :"https://helpx.adobe.com/security/products/flash-player/apsa16-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
if(version_in_range(version:playerVer, test_version:"20.0", test_version2:"21.0.0.240"))
{
  report =  report_fixed_ver(installed_version:playerVer, fixed_version:"21.0.0.241");
  security_message(data:report);
  exit(0);
}