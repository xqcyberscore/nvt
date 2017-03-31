###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln05_feb17.nasl 5448 2017-03-01 06:27:33Z cfi $
#
# Apple Mac OS X Multiple Vulnerabilities-05 February-2017
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810571");
  script_version("$Revision: 5448 $");
  script_cve_id("CVE-2016-4683", "CVE-2016-4671", "CVE-2016-4681");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-01 07:27:33 +0100 (Wed, 01 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-02-28 09:04:00 +0530 (Tue, 28 Feb 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-05 February-2017");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  - A memory corruption issue in 'Core Image'.
  - Multiple out-of-bounds read and write errors in 'SGI parsing'.
  - An out-of-bounds write error in 'ImageIO'.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to execute arbitrary code.

  Impact Level: System");

  script_tag(name: "affected" , value:"Apple Mac OS X versions 10.11.x through 
  10.11.6");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.12.1 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT207275");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
osName = "";
osVer = "";

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

## Check for the Mac OS X
if("Mac OS X" >< osName)
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.11", test_version2:"10.11.6"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.1");
    security_message(data:report);
    exit(0);
  }
}
