###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln01_dec15.nasl 6211 2017-05-25 09:04:14Z teissa $
#
# Apple Mac OS X Multiple Vulnerabilities-01 December-15
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
  script_oid("1.3.6.1.4.1.25623.1.0.807000");
  script_version("$Revision: 6211 $");
  script_cve_id("CVE-2015-7044", "CVE-2015-7045", "CVE-2015-7052", "CVE-2015-7059",
                "CVE-2015-7060", "CVE-2015-7061", "CVE-2015-7062", "CVE-2015-7063",
                "CVE-2015-7067", "CVE-2015-7071", "CVE-2015-7076", "CVE-2015-7077",
                "CVE-2015-7078", "CVE-2015-7106", "CVE-2015-7108", "CVE-2015-7109",
                "CVE-2015-7110");
  script_bugtraq_id(78735, 78721, 78733);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-25 11:04:14 +0200 (Thu, 25 May 2017) $");
  script_tag(name:"creation_date", value:"2015-12-15 12:46:20 +0530 (Tue, 15 Dec 2015)");
  script_name("Apple Mac OS X Multiple Vulnerabilities-01 December-15");

  script_tag(name: "summary" , value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to
  - An error in Bluetooth HCI interface.
  - An error in IOAcceleratorFamily.
  - An error in Disk Images component.
  - The System Integrity Protection feature mishandles union mounts.
  - The Keychain Access improperly interacts with Keychain Agent.
  - The Kext tools mishandles kernel-extension loading.
  - Error in in ASN.1 decode, kernel loader in EF, IOThunderboltFamily,in File
    Bookmark component.
  - The Multiple errors in Intel Graphics Driver component.
  - The Use-after-free error in Hypervisor.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to obtain sensitive information, execute arbitrary code, gain privileges,
  cause a denial of service, to spoof, to bypass protection mechanism.

  Impact Level: System");

  script_tag(name: "affected" , value:"Apple Mac OS X versions before 10.11.2");

  script_tag(name: "solution" , value:"Upgrade to Apple Mac OS X version
  10.11.2 or later. For more updates refer to https://www.apple.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.apple.com/HT205637");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2015/Dec/msg00005.html");
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
  if(version_is_less(version:osVer, test_version:"10.11.2"))
  {
    report = 'Installed Version: ' + osVer + '\nFixed Version: 10.11.2\n';
    security_message(data:report);
    exit(0);
  }
}
