###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-063.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2859537)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "
  Impact Level: System";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902990");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-2556", "CVE-2013-3196", "CVE-2013-3197", "CVE-2013-3198");
  script_bugtraq_id(58566, 61682, 61683, 1684);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-14 08:43:13 +0530 (Wed, 14 Aug 2013)");
  script_name("Microsoft Windows Kernel Privilege Elevation Vulnerabilities (2859537)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-063.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to,
- An error within Address Space Layout Randomization (ASLR) implementation
  can be exploited to bypass the ASLR security feature.
- Multiple error within the NT Virtual DOS Machine (NTVDM) subsystem.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code with kernel-mode privileges and or corrupt memory.";

  tag_affected =
"Microsoft Windows 8
Microsoft Windows XP x32 Edition Service Pack 3 and prior
Microsoft Windows 2003 x32 Edition Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior ";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-063";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54406");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2859537");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-063");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win7x64:2, win2008:3,
   win2008r2:2, win8:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from ntoskrnl.exe file
exeVer = fetch_file_version(sysPath, file_name:"system32\ntoskrnl.exe");
if(!exeVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Grep for ntoskrnl.exe < 5.1.2600.6419
  if(version_is_less(version:exeVer, test_version:"5.1.2600.6419")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003 x86
else if(hotfix_check_sp(win2003:3) > 0)
{
  ## Grep for ntoskrnl.exe version < 5.2.3790.5190
  if(version_is_less(version:exeVer, test_version:"5.2.3790.5190")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for ntoskrnl.exe version
  if(version_is_less(version:exeVer, test_version:"6.0.6002.18881") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23153")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for ntoskrnl.exe version
  if(version_is_less(version:exeVer, test_version:"6.1.7601.18205") ||
     version_in_range(version:exeVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22378")){
    security_message(0);
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1) > 0)
{
 ## Check for ntoskrnl.exe version
  if(version_is_less(version:exeVer, test_version:"6.2.9200.16659") ||
     version_in_range(version:exeVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20771")){
    security_message(0);
  }
  exit(0);
}
