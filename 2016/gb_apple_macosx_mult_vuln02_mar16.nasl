###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_mar16.nasl 4635 2016-11-28 08:14:54Z antu123 $
#
# Apple Mac OS X Multiple Vulnerabilities-02 March-2016
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806695");
  script_version("$Revision: 4635 $");
  script_cve_id("CVE-2016-1754", "CVE-2016-1755", "CVE-2016-1759", "CVE-2016-1761",
                "CVE-2016-1765", "CVE-2015-8472", "CVE-2015-1819", "CVE-2015-5312", 
                "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7942", "CVE-2015-8035", 
                "CVE-2015-8242", "CVE-2016-1762", "CVE-2016-0777", "CVE-2016-0778", 
                "CVE-2015-5333", "CVE-2015-5334", "CVE-2014-9495", "CVE-2015-0973", 
                "CVE-2016-1791", "CVE-2016-1800", "CVE-2016-1833", "CVE-2016-1834", 
                "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", 
                "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-1841", "CVE-2016-1847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-11-28 09:14:54 +0100 (Mon, 28 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:35 +0530 (Fri, 01 Apr 2016)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 March-2016");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists. For details
  refer the reference links.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service (memory corruption),
  gain access to potentially sensitive information, trigger a dialing action via a
  tel: URL, bypass a code-signing protection mechanism.
  Impact Level: System");

  script_tag(name: "affected" , value:"Apple Mac OS X versions 10.9.x before 10.9.5
  and 10.10.x before 10.10.5");

  script_tag(name: "solution" , value:"Apply the security patch or upgrade to Apple
  Mac OS X version 10.11.4 or later. 
  For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_xref(name : "URL" , value : "https://support.apple.com/en-us/HT206167");
  script_xref(name : "URL" , value : "https://support.apple.com/en-vn/HT206172");
  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT206567");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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
if("Mac OS X" >< osName && osVer =~ "^(10\.(9|10))")
{
  ## Check the affected OS versions
  if(version_in_range(version:osVer, test_version:"10.9.0", test_version2:"10.9.5")||
     version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.5"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"Apply Patch");
    security_message(data:report);
    exit(0);
  }
}
