###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_powershell_sec_bypass_vuln_july18_win.nasl 10558 2018-07-20 14:08:23Z santu $
#
# Microsoft PowerShell Core Security Feature Bypass Vulnerability July18 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813697");
  script_version("$Revision: 10558 $");
  script_cve_id("CVE-2018-8356");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-20 16:08:23 +0200 (Fri, 20 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-20 11:03:48 +0530 (Fri, 20 Jul 2018)");
  script_name("Microsoft PowerShell Core Security Feature Bypass Vulnerability July18 (Windows)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2018-8356.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect nvt and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft .NET Framework 
  components do not correctly validate certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers 
  to present expired certificates when challenged.

  Impact Level: Application");

  script_tag(name:"affected", value:"PowerShell Core versions 6.x prior to 6.0.3 
  and 6.1.x prior to 6.1.0-preview.4 on Windows.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.0.3 or 
  6.1.0-preview.4 or later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "https://github.com/PowerShell/PowerShell");
  script_xref(name : "URL" , value : "https://github.com/PowerShell/Announcements/issues/6");
  script_xref(name : "URL" , value : "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8356");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
psVer = infos['version'];
psPath = infos['location'];

if(version_in_range(version:psVer, test_version:"6.0", test_version2:"6.0.2")){
  fix = "6.0.3";
}

else if(version_in_range(version:psVer, test_version:"6.1", test_version2:"6.1.0.3")){
  fix = "6.1.0-preview.4";
}

if(fix)
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:fix, install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);
