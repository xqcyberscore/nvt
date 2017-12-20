###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_mult_vuln01_apr14_win.nasl 2014-04-01 12:10:22Z Apr$
#
# Adobe Flash Player Multiple Vulnerabilities - 01 Apr14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804350";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8178 $");
  script_cve_id("CVE-2014-0506", "CVE-2014-0510");
  script_bugtraq_id(66208, 66241);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 14:42:38 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2014-04-01 12:15:19 +0530 (Tue, 01 Apr 2014)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - 01 Apr14 (Windows)");

  tag_summary =
"This host is installed with Adobe Flash Player and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws exist due to an use-after-free error and some other unspecified error.";

  tag_impact =
"Successful exploitation will allow attacker to conduct denial of service or
potentially execute arbitrary code.

Impact Level: System/Application";

  tag_affected =
"Adobe Flash Player version 12.0.0.77 on Windows.";

  tag_solution =
"Upgrade Flash Player to version 13.0.0.182 or later,
For updates refer to http://get.adobe.com/flashplayer";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://securitytracker.com/id?1029969");
  script_xref(name : "URL" , value : "https://www.hkcert.org/my_url/en/alert/14033103");
  script_xref(name : "URL" , value : "http://www.pwn2own.com/2014/03/pwn2own-results-for-wednesday-day-one");
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
if(!playerVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_equal(version:playerVer, test_version:"12.0.0.77"))
{
  security_message(0);
  exit(0);
}
