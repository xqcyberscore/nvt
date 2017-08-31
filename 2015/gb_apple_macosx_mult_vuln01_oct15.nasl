###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_oct15.nasl 6534 2017-07-05 09:58:29Z teissa $
#
# Apple Mac OS X Multiple Vulnerabilities-01 October-15
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
  script_oid("1.3.6.1.4.1.25623.1.0.806148");
  script_version("$Revision: 6534 $");
  script_cve_id("CVE-2015-7035", "CVE-2015-7021", "CVE-2015-7020", "CVE-2015-7019",
                "CVE-2015-7016", "CVE-2015-7007", "CVE-2015-7003", "CVE-2015-6987",
                "CVE-2015-6985", "CVE-2015-6984", "CVE-2015-5945", "CVE-2015-5944",
                "CVE-2015-5943", "CVE-2015-5938", "CVE-2015-5934", "CVE-2015-5933",
                "CVE-2015-5932", "CVE-2015-7024", "CVE-2015-6980");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-05 11:58:29 +0200 (Wed, 05 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-10-29 12:54:16 +0530 (Thu, 29 Oct 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 October-15");

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

  script_tag(name: "affected" , value:"Apple Mac OS X versions before 10.11.1");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.11.1 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT205317");
  script_xref(name : "URL" , value : "https://support.apple.com/en-in/HT205375");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2015/Oct/msg00007.html");
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
  if(version_is_less(version:osVer, test_version:"10.11.1"))
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version: 10.11.1\n';
    security_message(data:report);
    exit(0);
  }
}
