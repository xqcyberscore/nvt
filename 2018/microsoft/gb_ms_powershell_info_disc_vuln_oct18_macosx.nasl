###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_powershell_info_disc_vuln_oct18_macosx.nasl 11902 2018-10-15 09:26:53Z santu $
#
# Microsoft PowerShell Core Information Disclosure Vulnerability Oct18 (Mac OS X)
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

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814091");
  script_version("$Revision: 11902 $");
  script_cve_id("CVE-2018-8292");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 11:26:53 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-11 12:17:00 +0530 (Thu, 11 Oct 2018)");
  script_name("Microsoft PowerShell Core Information Disclosure Vulnerability Oct18 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2018-8292.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when .NET Core when HTTP
  authentication information is inadvertently exposed in an outbound request that
  encounters an HTTP redirect.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information and use the information to further compromise
  the web application.");

  script_tag(name:"affected", value:"PowerShell Core versions 6.x prior to 6.1.0
  on Mac OS X.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.1.0 or
  later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/7");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell/issues/7981");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_macosx.nasl");
  script_mandatory_keys("PowerShell/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
psVer = infos['version'];
psPath = infos['location'];

if(psVer =~ "^6\." && version_is_less(version:psVer, test_version:"6.1.0")){
  fix = "6.1.0";
}

## Preview versions and release candidate versions
## v6.1.0-preview.4 = 6.1.0.4, v6.1.0-preview.1 = 6.1.0.1, v6.1.0-preview.2 = 6.1.0.2, v6.1.0-preview.3 = 6.1.0.3, 6.1.0-rc.1
affected = make_list('6.1.0.1', '6.1.0.2', '6.1.0.3', '6.1.0.4', '6.1.0-rc.1');
foreach version (affected)
{
  if(psVer == version){
   fix = "6.1.0";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:fix, install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);
