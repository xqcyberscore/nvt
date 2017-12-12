###############################################################################
# OpenVAS Vulnerability Test
# Id$
#
# Mozilla Firefox ESR Security Updates(mfsa_2017-28_2017-29)-Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812326");
  script_version("$Revision: 8056 $");
  script_cve_id("CVE-2017-7845", "CVE-2017-7843" );
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 13:47:50 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-08 10:38:59 +0530 (Fri, 08 Dec 2017)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2017-28_2017-29)-Windows");

  script_tag(name: "summary" , value:"This host is installed with Mozilla Firefox
  ESR and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The multiple flaws exists due to,
  - Buffer overflow when drawing and validating elements with ANGLE library using
    Direct 3D 9.
  - Web worker in Private Browsing mode can write IndexedDB data.");

  script_tag(name: "impact" , value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code on affected system or cause
  a denial of service condition and bypass private-browsing protections uniquely
  fingerprinting visitors.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Mozilla Firefox ESR version before 
  52.5.2 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox ESR version 52.5.2
  or later, For updates refer to http://www.mozilla.com/en-US/firefox/all.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-28/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

ffVer = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"52.5.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"52.5.2", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
