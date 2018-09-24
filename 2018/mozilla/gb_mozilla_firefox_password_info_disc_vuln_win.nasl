###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_password_info_disc_vuln_win.nasl 11544 2018-09-21 20:30:26Z cfischer $
#
# Mozilla Firefox 'Password' Information Disclosure Vulnerability (Windows)
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813894");
  script_version("$Revision: 11544 $");
  script_cve_id("CVE-2018-12383");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 22:30:26 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-06 13:22:59 +0530 (Thu, 06 Sep 2018)");
  script_name("Mozilla Firefox 'Password' Information Disclosure Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to setting a master password
  post-Firefox 58 does not delete unencrypted previously stored passwords.");

  script_tag(name:"impact", value:"Successful exploitation will allow the
  exposure of stored password data outside of user expectations.");

  script_tag(name:"affected", value:"Mozilla Firefox version 58 through 61.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 62 or later,
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-20");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_in_range(version:ffVer, test_version:"58.0", test_version2:"61.0.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"62", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(0);
