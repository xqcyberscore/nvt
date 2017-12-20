###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_code_exec_n_dos_vuln_nov13_win.nasl 8176 2017-12-19 12:50:00Z cfischer $
#
# Adobe AIR Code Execution and DoS Vulnerabilities Nov13 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804148";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8176 $");
  script_cve_id("CVE-2013-5329", "CVE-2013-5330");
  script_bugtraq_id(63680, 63680);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:50:00 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-11-19 15:16:28 +0530 (Tue, 19 Nov 2013)");
  script_name("Adobe AIR Code Execution and DoS Vulnerabilities Nov13 (Windows)");

  tag_summary =
"This host is installed with Adobe AIR and is prone to remote code execution and
denial of service vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws are due to multiple unspecified errors.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code, cause
denial of service (memory corruption) and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Adobe AIR before 3.9.0.1210 on Windows";

  tag_solution =
"Update to Adobe AIR version 3.9.0.1210 or later
For updates refer to  http://get.adobe.com/air";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55527");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-26.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
airVer = "";

## Get version
if(!airVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:airVer, test_version:"3.9.0.1210"))
{
  security_message(0);
  exit(0);
}
