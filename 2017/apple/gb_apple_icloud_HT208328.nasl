###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_icloud_HT208328.nasl 8291 2018-01-04 09:51:36Z asteins $
#
# Apple iCloud Security Updates HT208328)
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

CPE = "cpe:/a:apple:icloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812258");
  script_version("$Revision: 8291 $");
  script_cve_id("CVE-2017-13864", "CVE-2017-7156", "CVE-2017-7157", "CVE-2017-13856", 
                "CVE-2017-13870", "CVE-2017-13866", "CVE-2017-7160");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 10:51:36 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 16:00:28 +0530 (Thu, 14 Dec 2017)");
  script_name("Apple iCloud Security Updates( HT208328 )");

  script_tag(name:"summary", value:"This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The multiple flaws exists due to,

  - A privacy issue existed in the use of client certificates.

  - Multiple memory corruption issues.");

  script_tag(name: "impact" , value:"Successful exploitation of these
  vulnerabilities will allow remote attacker to track a user and also 
  arbitrary code execution.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Apple iCloud versions before 7.2");

  script_tag(name: "solution" , value:"Upgrade to Apple iCloud 7.2 or later.
  For updates refer to http://www.apple.com/support.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://support.apple.com/en-us/HT208328");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_apple_icloud_detect_win.nasl");
  script_mandatory_keys("apple/icloud/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = "";
vers = "";
path = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"7.2"))
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.2", install_path:path );
  security_message(data:report);
  exit(0);
}
exit(0);
