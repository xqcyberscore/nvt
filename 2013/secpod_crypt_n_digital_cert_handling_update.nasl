###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_crypt_n_digital_cert_handling_update.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Update to Improve Cryptography and Digital Certificate Handling (2854544)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to perform
  man-in-the-middle attack during a Windows Update session that basically
  redirects the user's machine to a phony update with the malware.
  Impact Level: System";

tag_affected = "Microsoft Windows 8
  Microsoft Windows Server 2012
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "The flaw is due to a Flame modules named 'Gadget' and 'Munch', used to infect
  other machines in the same network as the targeted machine.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/advisory/2854544";
tag_summary = "This host is missing an important security update according to
  Microsoft Security Advisory (2854544).";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903310");
  script_version("$Revision: 9353 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-12 12:56:11 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Update to Improve Cryptography and Digital Certificate Handling (2854544)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2813430");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2854544");
  script_xref(name : "URL" , value : "http://www.darkreading.com/attacks-breaches/flame-burns-microsoft-with-digital-certi/240001452");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
   win8:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Crypt32.dll file
exeVer = fetch_file_version(sysPath, file_name:"system32\Crypt32.dll");
if(!exeVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Crypt32.dll version
  if(version_is_less(version:exeVer, test_version:"6.0.6002.18823") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23094")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Crypt32.dll version
  if(version_is_less(version:exeVer, test_version:"6.1.7601.18142") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22310")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Check for Crypt32.dll version
  if(version_is_less(version:exeVer, test_version:"6.2.9200.16579")){
    security_message(0);
  }
  exit(0);
}
