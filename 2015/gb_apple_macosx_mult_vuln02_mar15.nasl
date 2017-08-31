###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln02_mar15.nasl 6601 2017-07-07 10:00:10Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities -02 Mar15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805484");
  script_version("$Revision: 6601 $");
  script_cve_id("CVE-2014-8839", "CVE-2014-8836");
  script_bugtraq_id(72328);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-07 12:00:10 +0200 (Fri, 07 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-03-05 17:54:00 +0530 (Thu, 05 Mar 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities -02 Mar15");
  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to,
  - The flaw in Spotlight that is triggered as the status of Mails
    'load remote content in messages' setting is not properly checked
  - The flaw in the Bluetooth driver that is triggered can allow a specially
    crafted application to control the size of a write to kernel memory.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to determine the IP address of the recipient of an email, a local
  attacker to gain elevated privileges.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple Mac OS X version 10.10.x through
  10.10.1");

  script_tag(name: "solution", value:"Upgrade to Apple Mac OS X version 10.10.2
  For more updates refer to https://www.apple.com/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name : "URL" , value : "https://support.apple.com/en-us/HT204244");
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
  if(version_in_range(version:osVer, test_version:"10.10", test_version2:"10.10.1"))
  {
    fix = "10.10.2";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version:     ' + fix + '\n';
    security_message(data:report);
    exit(0);
  }
}
