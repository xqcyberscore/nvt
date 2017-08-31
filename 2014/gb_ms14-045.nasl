###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-045.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# MS Windows Kernel-Mode Drivers Privilege Escalation Vulnerabilities (2984615)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804807");
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2014-0318", "CVE-2014-1819", "CVE-2014-4064");
  script_bugtraq_id(69142, 69143, 69144);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-13 07:58:09 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("MS Windows Kernel-Mode Drivers Privilege Escalation Vulnerabilities (2984615)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-045";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws exist due to,
- An error within win32k.sys when handling window handle thread-owned objects.
- A double fetch error within win32k.sys when processing font files.
- An error related to Windows kernel pool.";

  tag_impact =
"Successful exploitation will allow attackers to disclose certain sensitive
information and gain escalated privileges.

Impact Level: System";

  tag_affected =
"Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows 8 x32/x64
Windows 8.1 x32/x64 Edition
Microsoft Windows Server 2012/R2";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-045";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2982791");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2976897");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2993651");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS14-045");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
win32SysVer="";
dxgkrnlVer= "";


## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

##Fetch file versions
win32SysVer = fetch_file_version(sysPath, file_name:"system32\win32k.sys");
dxgkrnlVer = fetch_file_version(sysPath, file_name:"system32\drivers\dxgkrnl.sys");

if(!win32SysVer && !dxgkrnlVer){
  exit(0);
}

##Windows Server 2003
if((hotfix_check_sp(win2003x64:3,win2003:3) > 0) && win32SysVer)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5418")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(win32SysVer)
  {
    ## Check for Win32k.sys version
    if(version_in_range(version:win32SysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.19170") ||
       version_in_range(version:win32SysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23475")){
      security_message(0);
    }
  }

  if(dxgkrnlVer)
  {
    ## Check for dxgkrnlVer version
    if(version_in_range(version:dxgkrnlVer, test_version:"7.0.6002.18000" , test_version2:"7.0.6002.19125") ||
       version_in_range(version:dxgkrnlVer, test_version:"7.0.6002.23000" , test_version2:"7.0.6002.23426")){
      security_message(0);
    }
  }
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(win32SysVer)
  {
    ## Check for Win32k.sys version version
    if(version_in_range(version:win32SysVer, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18576") ||
       version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22782")){
      security_message(0);
    }
  }

  if(dxgkrnlVer)
  {
    ## Check for dxgkrnlVer version
    if(version_in_range(version:dxgkrnlVer, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18509") ||
       version_in_range(version:dxgkrnlVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22719")){
      security_message(0);
    }
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(win32SysVer)
  {
    ## Check for Win32k.sys version
    if(version_is_less(version:win32SysVer, test_version:"6.2.9200.17000", test_version2:"6.2.9200.17095") ||
       version_in_range(version:win32SysVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21213")){
     security_message(0);
    }
  }
  if(dxgkrnlVer)
  {
    ## Check for dxgkrnlVer version
    if(version_in_range(version:dxgkrnlVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.17030") ||
       version_in_range(version:dxgkrnlVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21147")){
     security_message(0);
    }
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Win32k.sys version
  if(win32SysVer && version_is_less(version:win32SysVer, test_version:"6.3.9600.17261")){
   security_message(0);
  }

  ## Check for dxgkrnlVer version
  if(dxgkrnlVer && version_is_less(version:dxgkrnlVer, test_version:"6.3.9600.17210")){
   security_message(0);
  }
  exit(0);
}
