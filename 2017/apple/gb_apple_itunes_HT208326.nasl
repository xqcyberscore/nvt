###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_HT208326.nasl 8263 2017-12-29 15:35:55Z santu $
#
# Apple iTunes Security Updates( HT208326 )
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812285");
  script_version("$Revision: 8263 $");
  script_cve_id("CVE-2017-13864", "CVE-2017-13866", "CVE-2017-13856", "CVE-2017-13870", 
                "CVE-2017-7156", "CVE-2017-7157", "CVE-2017-7160");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 16:35:55 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-28 14:47:56 +0530 (Thu, 28 Dec 2017)");
  script_name("Apple iTunes Security Updates( HT208326 )");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,

  - Multiple memory corruption issues.

  - A privacy issue existed in the use of client certificates.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to track users by 
  leveraging mishandling of client certificates and also execute arbitrary code 
  or cause a denial of service.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple iTunes versions before 12.7.2");

  script_tag(name: "solution" , value:"Upgrade to Apple iTunes 12.7.2 or later.
  For updates refer to http://www.apple.com/support.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT208326");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

ituneVer = "";
path = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
ituneVer = infos['version'];
path = infos['location'];

##12.7.2 == 12.7.2.58
if(version_is_less(version:ituneVer, test_version:"12.7.2.58"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.7.2", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
