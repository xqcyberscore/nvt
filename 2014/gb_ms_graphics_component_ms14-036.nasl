###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_graphics_component_ms14-036.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# Microsoft Windows Graphics Component Multiple Vulnerabilities (2967487)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804596");
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_bugtraq_id(67897, 67904);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-06-11 10:52:36 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Windows Graphics Component Multiple Vulnerabilities (2967487)");

  tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS14-036.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to,
- An error within Unicode Scripts Processor.
- An error within GDI+ when validating images.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code
and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2
Microsoft Windows 2003 x32 Edition Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior ";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-036";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58583");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2957503");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2957509");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Check for Windows 7, Windows Server 2008 R2, Windows Server 2008,
## Windows Vista, and Windows Server 2003
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2) > 0)
{
  ## Get Version from Usp10.dll
  dllVer = fetch_file_version(sysPath, file_name:"system32\Usp10.dll");
  if(!dllVer){
    exit(0);
  }

  ## Windows 2003 x86 and x64
  if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
  {
    ## Check version for Usp10.dll
    if(version_is_less(version:dllVer, test_version:"1.422.3790.5340")){
      security_message(0);
    }
    exit(0);
  }

  ## Windows Vista and Server 2008
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    ## Check for Usp10.dll version
    if(version_in_range(version:dllVer, test_version:"1.626.6002.18000", test_version2:"1.626.6002.19095")||
       version_in_range(version:dllVer, test_version:"1.626.6002.23000", test_version2:"1.626.6002.23385")){
      security_message(0);
    }
    exit(0);
  }

  ## Windows 7 and Server 2008r2
  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    ## Check for Usp10.dll version
    if(version_in_range(version:dllVer, test_version:"1.626.7601.18000", test_version2:"1.626.7601.18453")||
       version_in_range(version:dllVer, test_version:"1.626.7601.22000", test_version2:"1.626.7601.22665")){
      security_message(0);
    }
    exit(0);
  }
}

## Check for Windows 8.1
## Windows 8, and Windows Server 2012
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  ## Get Version from Gdi32.dll
  dllVer2 = fetch_file_version(sysPath, file_name:"system32\Gdi32.dll");

  ## Windows 8 and Server 2012
  if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    ## Check for Gdi32.dll version
    if(version_in_range(version:dllVer2, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16908")||
       version_in_range(version:dllVer2, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21031")){
      security_message(0);
    }
    exit(0);
  }

  ## Windows 8.1
  ## Currently we are not supporting Windows Server 2012 R2
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    ## Check for Gdi32.dll version
    dllVer3 = fetch_file_version(sysPath, file_name:"system32\Dwrite.dll");

    if(version_is_less(version:dllVer2, test_version:"6.3.9600.17111") ||
       version_is_less(version:dllVer3, test_version:"6.3.9600.17111")){
      security_message(0);
    }
    exit(0);
  }
}
