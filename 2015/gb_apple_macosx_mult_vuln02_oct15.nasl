###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_oct15.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Apple Mac OS X Multiple Vulnerabilities-02 October-15
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806154");
  script_version("$Revision: 5351 $");
  script_cve_id("CVE-2015-7761", "CVE-2015-7760", "CVE-2015-5922", "CVE-2015-5917",
                "CVE-2015-5915", "CVE-2015-5914", "CVE-2015-5913", "CVE-2015-5902",
                "CVE-2015-5901", "CVE-2015-5900", "CVE-2015-5897", "CVE-2015-5894",
                "CVE-2015-5893", "CVE-2015-5891", "CVE-2015-5890", "CVE-2015-5889",
                "CVE-2015-5888", "CVE-2015-5887", "CVE-2015-5884", "CVE-2015-5883",
                "CVE-2015-5878", "CVE-2015-5877", "CVE-2015-5875", "CVE-2015-5873",
                "CVE-2015-5872", "CVE-2015-5871", "CVE-2015-5870", "CVE-2015-5866",
                "CVE-2015-5865", "CVE-2015-5864", "CVE-2015-5854", "CVE-2015-5853",
                "CVE-2015-5849", "CVE-2015-5836", "CVE-2015-5833", "CVE-2015-5830",
                "CVE-2015-3785");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2015-10-29 13:24:34 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-02 October-15");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service, write to
  arbitrary files,  execute arbitrary code with system privilege.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple Mac OS X versions before 10.11");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.11 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT205267");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2015/Sep/msg00008.html");
  script_summary("Check for the vulnerable version of Apple Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
  if(version_is_less(version:osVer, test_version:"10.11"))
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version: 10.11\n';
    security_message(data:report);
    exit(0);
  }
}
