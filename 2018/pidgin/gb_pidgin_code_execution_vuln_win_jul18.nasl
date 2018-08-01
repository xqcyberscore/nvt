###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_code_execution_vuln_win_jul18.nasl 10692 2018-07-31 13:51:55Z santu $
#
# Pidgin 'Out-of-Bounds Write' Code Execution Vulnerability-(Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:pidgin:pidgin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813735");
  script_version("$Revision: 10692 $");
  script_cve_id("CVE-2017-2640");
  script_bugtraq_id(96775);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-31 15:51:55 +0200 (Tue, 31 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-30 16:05:18 +0530 (Mon, 30 Jul 2018)");
  script_name("Pidgin 'Out-of-Bounds Write' Code Execution Vulnerability-(Windows)");

  script_tag(name: "summary" , value:"This host is installed with Pidgin and is
  prone to code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an out-of-bounds
  write error while decoding invalid xml.");

  script_tag(name: "impact" , value:"Successful exploitation will allow an
  attacker to execute arbitrary code on affected system.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Pidgin before version 2.12.0 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Pidgin version 2.12.0 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.pidgin.im");
  script_xref(name:"URL", value:"https://pidgin.im/news/security/?id=109");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
pidVer = infos['version'];
path = infos['location'];

if(version_is_less(version:pidVer, test_version:"2.12.0"))
{
  report = report_fixed_ver(installed_version:pidVer, fixed_version:"2.12.0", install_path:path);
  security_message(data: report);
  exit(0);
}
