###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnet_core_sdk_dos_vuln_may18_win.nasl 10262 2018-06-20 02:57:24Z ckuersteiner $
#
# .NET Core SDK Denial of Service Vulnerability (Windows)
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
##########################################################################
CPE = "cpe:/a:microsoft:.netcore_sdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813190");
  script_version("$Revision: 10262 $");
  script_cve_id("CVE-2018-0765");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-06-20 04:57:24 +0200 (Wed, 20 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-15 14:17:38 +0530 (Tue, 15 May 2018)");
  script_name(".NET Core SDK Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary" , value:"This host is installed with .NET Core SDK
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight" , value:"The flaw exists due to an error when .NET
  and .NET Core improperly process XML documents.");

  script_tag(name:"impact" , value:"Successful exploitation will allow an attacker
  to cause a denial of service against a .NET application.

  Impact Level: System/Application");

  script_tag(name:"affected" , value:".NET Core SDK 2.x prior to version 2.1.200");

  script_tag(name:"solution" , value:"Upgrade to .NET Core SDK to version 2.1.200
  or later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0765");
  script_xref(name : "URL" , value : "https://github.com/dotnet/announcements/issues/67");
  script_xref(name : "URL" , value : "https://github.com/dotnet/core/blob/master/release-notes/download-archives/2.1.200-sdk-download.md");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_asp_dotnet_core_detect_win.nasl");
  script_mandatory_keys(".NET/Core/SDK/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
coreVers = infos['version'];
path = infos['location'];

if(coreVers =~ "^(2\.)" && version_is_less(version:coreVers, test_version:"2.1.200"))
{
  report = report_fixed_ver(installed_version:coreVers, fixed_version:"2.1.200", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
