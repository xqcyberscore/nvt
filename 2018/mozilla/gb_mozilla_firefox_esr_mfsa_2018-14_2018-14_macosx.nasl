###############################################################################
# OpenVAS Vulnerability Test
# Id$
#
# Mozilla Firefox ESR Security Updates(mfsa_2018-14_2018-14)-MAC OS X
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813395");
  script_version("$Revision: 10124 $");
  script_cve_id("CVE-2018-6126" );
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-07 15:56:22 +0200 (Thu, 07 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-07 10:54:24 +0530 (Thu, 07 Jun 2018)");
  script_name("Mozilla Firefox ESR Security Updates(mfsa_2018-14_2018-14)-MAC OS X");

  script_tag(name: "summary" , value:"This host is installed with 
  Mozilla Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The Flaw exists due to a heap buffer 
  overflow can occur in the Skia library when rasterizing paths using a 
  maliciously crafted SVG file with anti-aliasing turned off.");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow remote attackers to result in a potentially 
  exploitable crash.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"Mozilla Firefox ESR version before 
  52.8.1  and 60.x before 60.0.2 on MAC OS X.");

  script_tag(name: "solution" , value:"Upgrade to Mozilla Firefox ESR version 52.8.1
  or 60.0.2 or later, For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-14/");
  script_xref(name:"URL", value:"https://www.mozilla.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"52.8.1")){
  fix = "52.8.1";
}

else if(ffVer =~ "^(60\.0)" && version_is_less(version:ffVer, test_version:"60.0.2")){
  fix = "60.0.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:fix, install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(0);