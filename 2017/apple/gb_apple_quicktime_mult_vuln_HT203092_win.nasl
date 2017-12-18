###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_HT203092_win.nasl 8136 2017-12-15 10:59:51Z santu $
#
# Apple QuickTime Multiple Vulnerabilities-HT203092 (Windows)
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

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812350");
  script_version("$Revision: 8136 $");
  script_cve_id("CVE-2014-4351", "CVE-2014-4350", "CVE-2014-4979", "CVE-2014-1391");
  script_bugtraq_id(68852, 70643, 69908, 69907);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 11:59:51 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-14 17:26:49 +0530 (Thu, 14 Dec 2017)");
  script_name("Apple QuickTime Multiple Vulnerabilities-HT203092 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Apple QuickTime
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,

  - A memory corruption issue existed in the handling of RLE encoded movie files.

  - A memory corruption issue existed in the handling of the 'mvhd' atoms.

  - A buffer overflow existed in the handling of MIDI files.

  - A buffer overflow existed in the handling of audio samples.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause unexpected application termination or run arbitrary code
  on affected system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple QuickTime version before 7.7.6 on
  Windows.");

  script_tag(name: "solution" , value:"Upgrade to Apple QuickTime version 7.7.6
  or later. For updates refer to http://support.apple.com/downloads");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT203092");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
quickVer = "";

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
quickVer = infos['version'];
quickPath = infos['location'];

if(version_is_less(version:quickVer, test_version:"7.76.80.95"))
{
  report = report_fixed_ver(installed_version:quickVer, fixed_version: "7.7.6", install_path:quickPath);
  security_message(data: report);
  exit(0);
}
exit(0);
