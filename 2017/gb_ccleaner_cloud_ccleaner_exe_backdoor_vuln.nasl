###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ccleaner_cloud_ccleaner_exe_backdoor_vuln.nasl 7202 2017-09-20 12:47:53Z santu $
#
# CCleaner Cloud 'CCleaner.exe' Backdoor Trojan Vulnerability (Windows)
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

CPE = "cpe:/a:piriform:ccleaner_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811780");
  script_version("$Revision: 7202 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-20 14:47:53 +0200 (Wed, 20 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-19 13:28:32 +0530 (Tue, 19 Sep 2017)");
  script_name("CCleaner Cloud 'CCleaner.exe' Backdoor Trojan Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with CCleaner Cloud
  agent and is prone to backdoor trojan installation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an unauthorized
  modification of the 'CCleaner.exe' binary resulted in an insertion of a two-stage
  backdoor.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to take complete control of system and run code on affected system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"CCleaner Cloud Agent version 1.07.3191");

  script_tag(name: "solution" , value:"Upgrade to CCleaner Cloud version 
  1.7.0.3214 or later.For updates refer to https://www.piriform.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value:"http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html");
  script_xref(name : "URL" , value:"http://www.piriform.com/news/blog/2017/9/18/security-notification-for-ccleaner-v5336162-and-ccleaner-cloud-v1073191-for-32-bit-windows-users");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ccleaner_cloud_agent_detect_win.nasl");
  script_mandatory_keys("CCleaner/Cloud/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ccVer = "";

## Get OS Architecture
os_arch = get_kb_item("SMB/Windows/Arch");

## Only 32-bit platform is affected
if((!os_arch) || ("x86" >!< os_arch)){
  exit(0);
}

## Get version
if(!ccVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for vulnerable version, 1.07.3191
## 1.07.3191 = 1.7.0.3191
if(ccVer == "1.7.0.3191")
{
  report = report_fixed_ver(installed_version:ccVer, fixed_version:"1.7.0.3214");
  security_message(data:report);
  exit(0);
}
exit(0);
