###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flexera_installshield_privilege_escalation_vuln.nasl 8200 2017-12-20 13:48:45Z cfischer $
#
# Flexera InstallShield Privilege Escalation Vulnerability
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

CPE = "cpe:/a:flexerasoftware:installshield:2015";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809006");
  script_version("$Revision: 8200 $");
  script_cve_id("CVE-2016-2542");
  script_bugtraq_id(84213);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:48:45 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2016-08-19 19:16:31 +0530 (Fri, 19 Aug 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Flexera InstallShield Privilege Escalation Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Flexera
  InstallShield and is prone to privilege escalation vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an untrusted search path 
  vulnerability in Flexera InstallShield.");

  script_tag(name: "impact" , value:"Successful exploitation will allow a local
  attacker to gain privileges via a Trojan horse DLL in the current working 
  directory of a setup-launcher executable file.

  Impact Level: System");

  script_tag(name: "affected" , value:"Flexera InstallShield through 2015 SP1.");

  script_tag(name: "solution" , value:"Apply the patch from the link mentioned in 
  reference. 
  For updates refer to http://www.flexerasoftware.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://flexeracommunity.force.com/customer/articles/INFO/Best-Practices-to-Avoid-Windows-Setup-Launcher-Executable-Issues");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_flexera_installshield_detect_win.nasl");
  script_mandatory_keys("Flexera/InstallShield/Win/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
inshieldVer = "";
report = "";
sysPath = "";
sysVer = 0;
minRequireVer = 0;

## Get version
if(!inshieldVer = get_kb_item("Flexera/InstallShield/Win/Ver")){
  exit(0);
}

## Get the location
sysPath = get_app_location(cpe:CPE);
if(!sysPath)
{
  CPE = "cpe:/a:flexerasoftware:installshield:2014";
  sysPath = get_app_location(cpe:CPE);
  if(!sysPath){
    CPE = "cpe:/a:flexerasoftware:installshield:2013";
  }
  if(!sysPath){
    exit(0);
  }
}

## Get dotnetfx.exe file version
sysVer = fetch_file_version(sysPath, file_name:"Redist\0409\i386\dotnetfx.exe");
if(!sysVer){
  exit(0);
}

## Check for InstallShield version
if(inshieldVer =~ "^22"){
  minRequireVer = "22.0.0.360";
}
else if(inshieldVer =~ "^21"){
  minRequireVer = "21.0.0.350";
}
else{
  minRequireVer = "20.0.0.530";
}

## Checking Hotfix IOJ-1745445 is already applied or not
## Check for the plugDaemonHost.dll version 
if(version_is_less(version:sysVer, test_version:minRequireVer))
{
  report = report_fixed_ver(installed_version:inshieldVer, fixed_version:"Apply the hotfix");
  security_message(data:report);
  exit(0);
}
