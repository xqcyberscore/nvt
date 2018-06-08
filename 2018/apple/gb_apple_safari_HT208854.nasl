###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_HT208854.nasl 10124 2018-06-07 13:56:22Z santu $
#
# Apple Safari Security Updates(HT208854)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813509");
  script_version("$Revision: 10124 $");
  script_cve_id("CVE-2018-4247", "CVE-2018-4205", "CVE-2018-4232", "CVE-2018-4246", 
                "CVE-2018-4192", "CVE-2018-4188", "CVE-2018-4214", "CVE-2018-4201", 
                "CVE-2018-4218", "CVE-2018-4233", "CVE-2018-4199", "CVE-2018-4190", 
                "CVE-2018-4222" );
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 15:56:22 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-04 13:35:10 +0530 (Mon, 04 Jun 2018)");
  script_name("Apple Safari Security Updates(HT208854)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,

  - A permissions issue in the handling of web browser cookies.

  - A type confusion issue in memory handling.

  - A race condition issue in locking.

  - A memory corruption issue in input validation.

  - A buffer overflow issue in memory handling.

  - Credentials were unexpectedly sent when fetching CSS mask images.

  - An out-of-bounds read issue in input validation.");

  script_tag(name: "impact" , value:"Successful exploitation of will allow remote
  attackers to cause a denial of service, conduct spoofing attack, overwrite 
  cookies, execute arbitrary code, crash Safari and leak sensitive data.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Apple Safari versions before 11.1.1");

  script_tag(name: "solution" , value:"Upgrade to Apple Safari 11.1.1 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT208854");
  script_xref(name : "URL" , value : "https://www.apple.com");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
sVer = infos['version'];
sPath = infos['location'];

if(version_is_less(version:sVer, test_version:"11.1.1"))
{
  report = report_fixed_ver(installed_version:sVer, fixed_version:"11.1.1", install_path:sPath);
  security_message(data:report);
  exit(0);
}
exit(0);
