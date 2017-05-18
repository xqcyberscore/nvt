###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flexera_installanywhere_privilege_escalation_vuln_macosx.nasl 5759 2017-03-29 09:01:08Z teissa $
#
# Flexera InstallAnywhere Privilege Escalation Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:flexerasoftware:installanywhere";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809019");
  script_version("$Revision: 5759 $");
  script_cve_id("CVE-2016-4560");
  script_bugtraq_id(90979);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-29 11:01:08 +0200 (Wed, 29 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("Flexera InstallAnywhere Privilege Escalation Vulnerability (Mac OS X)");

  script_tag(name: "summary" , value:"The host is installed with Flexera
  InstallAnywhere and is prone to privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an untrusted search path 
  vulnerability in Flexera InstallAnywhere.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a local
  attacker to gain privileges via a Trojan horse DLL in the current working 
  directory of a setup-launcher executable file.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Flexera InstallAnywhere all versions on Mac OS X.");

  script_tag(name: "solution" , value:"Apply the hotfix from the link mentioned in 
  reference. For updates refer to http://www.flexerasoftware.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://flexeracommunity.force.com/customer/articles/INFO/Best-Practices-to-Avoid-Windows-Setup-Launcher-Executable-Issues");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_flexera_installanywhere_detect_macosx.nasl");
  script_mandatory_keys("InstallAnywhere/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
installVer = "";
report = "";

## Get version
if(!installVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Checking for vulnerable version
if(version_is_less_equal(version:installVer, test_version:"17.0"))
{
  report = report_fixed_ver(installed_version:installVer, fixed_version:"Apply the hotfix");
  security_message(data:report);
  exit(0);
}
