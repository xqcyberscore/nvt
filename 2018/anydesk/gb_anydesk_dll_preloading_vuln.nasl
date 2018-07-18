###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_anydesk_dll_preloading_vuln.nasl 10538 2018-07-18 10:58:40Z santu $
#
# AnyDesk DLL Preloading Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:anydesk:anydesk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813554");
  script_version("$Revision: 10538 $");
  script_cve_id("CVE-2018-13102");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-18 12:58:40 +0200 (Wed, 18 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-06 16:47:10 +0530 (Fri, 06 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("AnyDesk DLL Preloading Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with AnyDesk and is
  prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaws exist due to improper sanitization
  of an unknown function in the component DLL Loader.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privilege and gain control of the application.

  Impact Level: Application");

  script_tag(name:"affected", value:"AnyDesk version before 4.1.3 on Windows 7
  SP1");

  script_tag(name:"solution", value:"Update AnyDesk to version 4.1.3 or above.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value : "https://download.anydesk.com/changelog.txt");
  script_xref(name:"URL", value : "https://anydesk.com/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_anydesk_detect_win.nasl");
  script_mandatory_keys("AnyDesk/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(win7:1) <= 0)  exit(0);

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
adVer = infos['version'];
adPath = infos['location'];

if(version_is_less(version:adVer, test_version:"4.1.3"))
{
  report = report_fixed_ver(installed_version:adVer, fixed_version:"4.1.3", install_path: adPath);
  security_message(data:report);
  exit(0);
}
