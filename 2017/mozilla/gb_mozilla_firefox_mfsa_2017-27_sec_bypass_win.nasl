###############################################################################
# OpenVAS Vulnerability Test
# Id$
#
# Mozilla Firefox Security Bypass Vulnerability(mfsa_2017-27)-Windows
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812322");
  script_version("$Revision: 8027 $");
  script_cve_id("CVE-2017-7843");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 10:50:33 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-05 12:30:09 +0530 (Tue, 05 Dec 2017)");
  script_name("Mozilla Firefox Security Bypass Vulnerability(mfsa_2017-27)-Windows");

  script_tag(name: "summary" , value:"This host is installed with Mozilla
  Firefox and is prone to security bypass vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists as the web worker in private
  browsing mode can write IndexedDB data.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to bypass security restrictions.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Mozilla Firefox version before 57.0.1 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox version 57.0.1
  or later. For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-27");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

ffVer = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );

ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"57.0.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"57.0.1", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(0);
