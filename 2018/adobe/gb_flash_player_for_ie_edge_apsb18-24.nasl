###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flash_player_for_ie_edge_apsb18-24.nasl 10484 2018-07-11 14:03:19Z santu $
#
# Microsoft IE And Microsoft Edge Flash Player Multiple Vulnerabilities (apsb18-24)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player_internet_explorer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813644");
  script_version("$Revision: 10484 $");
  script_cve_id("CVE-2018-5008", "CVE-2018-5007");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-11 16:03:19 +0200 (Wed, 11 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-11 08:40:25 +0530 (Wed, 11 Jul 2018)");
  script_name("Microsoft IE And Microsoft Edge Flash Player Multiple Vulnerabilities (apsb18-24)");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  within Microsoft Edge or Internet Explorer and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  
  - An out-of-bounds read error.

  - A type Confusion error.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote 
  attackers to disclose sensitive information and also to conduct arbitrary code
  execution.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Flash Player within Microsoft Edge or
  Internet Explorer on,

  Windows 10 Version 1803 for x32/x64 Edition,

  Windows 10 Version 1607 for x32/x64 Edition,

  Windows 10 Version 1703 for x32/x64 Edition,

  Windows 10 Version 1709 for x32/x64 Edition,

  Windows 10 x32/x64 Edition,

  Windows 8.1 for x32/x64 Edition and

  Windows Server 2012/2012 R2/2016");

  script_tag(name: "solution", value:"Run Windows update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name: "URL" , value :"http://get.adobe.com/flashplayer");
  script_xref(name : "URL" , value :"https://helpx.adobe.com/security/products/flash-player/apsb18-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_flash_player_within_ie_edge_detect.nasl");
  script_mandatory_keys("AdobeFlash/IE_or_EDGE/Installed");
  exit(0);
}

include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012:1, win2012R2:1, win10:1,
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE))
{
  CPE = "cpe:/a:adobe:flash_player_edge";
  infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
}

flashVer = infos['version'];
if(!flashVer){
  exit(0);
}

flashPath = infos['location'];

if(flashPath){
  flashPath = flashPath + "\Flashplayerapp.exe";
} else {
  flashPath = "Could not find the install location";
}

if(version_is_less(version:flashVer, test_version:"30.0.0.134"))
{
  report = report_fixed_ver(file_checked:flashPath,
                            file_version:flashVer, vulnerable_range:"Less than 30.0.0.134");
  security_message(data:report);
  exit(0);
}
exit(0);
