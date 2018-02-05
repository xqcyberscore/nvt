##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_apsa18-01_macosx.nasl 8642 2018-02-02 13:14:25Z santu $
#
# Adobe Flash Player Zero-Day Remote Code Execution Vulnerability - Mac OS X
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812684");
  script_version("$Revision: 8642 $");
  script_cve_id("CVE-2018-4878");
  script_bugtraq_id(102893);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-02 14:14:25 +0100 (Fri, 02 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-02 11:00:27 +0530 (Fri, 02 Feb 2018)");
  script_name("Adobe Flash Player Zero-Day Remote Code Execution Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to a remote code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to a use-after-free 
  error in the flash player.");

  script_tag(name: "impact" , value:"Successful exploitation of this vulnerability
  will allow an attacker to execute arbitrary code on affected system and take 
  control of the affected system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Flash Player version 28.0.0.137 and
  earlier on Mac OS X.");

  script_tag(name: "solution", value:"No solution or patch is available as of
  2nd Feb, 2018. Information regarding this issue will be updated once solution
  details are available.
  For updates refer to http://get.adobe.com/flashplayer");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name: "URL" , value :"https://helpx.adobe.com/security/products/flash-player/apsa18-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"28.0.0.137"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
