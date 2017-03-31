###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln04_oct15.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# Apple Mac OS X Multiple Vulnerabilities-04 October-15
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
  script_oid("1.3.6.1.4.1.25623.1.0.806150");
  script_version("$Revision: 5351 $");
  script_cve_id("CVE-2013-1032", "CVE-2013-1031", "CVE-2013-1030", "CVE-2013-1029",
                "CVE-2013-1028", "CVE-2013-1027", "CVE-2013-1026", "CVE-2013-1025",
                "CVE-2013-1033");
  script_bugtraq_id(62375, 62374, 62377, 62382, 62371, 62370, 62369, 62368, 62378);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2015-10-29 13:55:31 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-04 October-15");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists. For details refer
  reference section.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, bypass intended launch
  restrictions and access restrictions, cause a denial of service and write to
  arbitrary files.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Apple Mac OS X versions before 10.8.5");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.8.5 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT202785");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2013/Sep/msg00002.html");
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
  if(version_is_less(version:osVer, test_version:"10.8.5"))
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version: 10.8.5\n';
    security_message(data:report);
    exit(0);
  }
}
