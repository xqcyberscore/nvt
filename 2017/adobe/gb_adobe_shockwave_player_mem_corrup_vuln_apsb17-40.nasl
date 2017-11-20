###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mem_corrup_vuln_apsb17-40.nasl 7790 2017-11-16 13:11:14Z santu $
#
# Adobe Shockwave Player Memory Corruption Vulnerability (APSB17-40)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812092");
  script_version("$Revision: 7790 $");
  script_cve_id("CVE-2017-11294");
  script_bugtraq_id(101836);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-16 14:11:14 +0100 (Thu, 16 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-16 11:32:08 +0530 (Thu, 16 Nov 2017)");
  script_name("Adobe Shockwave Player Memory Corruption Vulnerability (APSB17-40)");

  script_tag(name: "summary" , value: "This host is installed with Adobe Shockwave
  Player and is prone to memory corruption vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to some unspecified
  memory corruption error.");

  script_tag(name: "impact" , value: "Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the user running the affected
  application. Failed exploit attempts will likely result in denial-of-service
  conditions. 

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Shockwave Player version 12.2.9.199
  and earlier on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Shockwave Player version
  12.3.1.201 or later. For updates refer to http://get.adobe.com/shockwave");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://helpx.adobe.com/security/products/shockwave/apsb17-40.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

playerVer = "";
playerPath = "";

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
playerVer = infos['version'];
playerPath = infos['location'];

if(version_is_less_equal(version:playerVer, test_version:"12.2.9.199"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"12.3.1.201", install_path:playerPath);
  security_message(data:report);
  exit(0);
}
exit(0);
