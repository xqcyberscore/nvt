###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_virtualbox_security_bypass_vuln_apr17_win.nasl 6092 2017-05-10 07:02:40Z cfi $
#
# Oracle Virtualbox Security Bypass Vulnerability - 01 Apr17 (Windows)
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811011");
  script_version("$Revision: 6092 $");
  script_cve_id("CVE-2017-3538");
  script_bugtraq_id(97698);
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 09:02:40 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2017-04-25 15:26:47 +0530 (Tue, 25 Apr 2017)");
  script_name("Oracle Virtualbox Security Bypass Vulnerability - 01 Apr17 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Oracle VM
  VirtualBox and is prone to security bypass vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an unspecified error
  in the 'Shared Folder' component of the application.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to have an impact on availability, confidentiality and integrity.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VirtualBox versions prior to 5.0.34
  and prior to 5.1.16 on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Oracle VirtualBox 5.0.34 or 5.1.16 or later,
  For updates refer to https://www.virtualbox.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
virtualVer = "";
report = "";

## Get version
if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(virtualVer =~ "^(5\.0)")
{
  if(version_is_less(version:virtualVer, test_version:"5.0.34"))
  {
    fix = "5.0.34";
    VULN = TRUE;
  }
}

else if(virtualVer =~ "^(5\.1)")
{
  if(version_is_less(version:virtualVer, test_version:"5.1.16"))
  {
    fix = "5.1.16";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver( installed_version:virtualVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
