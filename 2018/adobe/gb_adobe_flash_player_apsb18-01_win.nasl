##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_apsb18-01_win.nasl 8646 2018-02-02 16:20:32Z cfischer $
#
# Adobe Flash Player Security Updates(apsb18-01)-Windows
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812716");
  script_version("$Revision: 8646 $");
  script_cve_id("CVE-2018-4871");
  script_bugtraq_id(102465);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-02 17:20:32 +0100 (Fri, 02 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-10 15:07:31 +0530 (Wed, 10 Jan 2018)");
  script_name("Adobe Flash Player Security Updates(apsb18-01)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Flash Player
  and is prone to an information disclosure vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name: "impact" , value:"Successful exploitation of this vulnerability
  will lead to information exposure.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Adobe Flash Player version before 
  28.0.0.137 on Windows.");

  script_tag(name: "solution", value:"Upgrade to Adobe Flash Player version
  28.0.0.137 or later.
  For updates refer to http://get.adobe.com/flashplayer");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name: "URL" , value :"https://helpx.adobe.com/security/products/flash-player/apsb18-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Grep for vulnerable version
if(version_is_less(version:vers, test_version:"28.0.0.137"))
{
  report =  report_fixed_ver(installed_version:vers, fixed_version:"28.0.0.137", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
