###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-039.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Microsoft Windows On-Screen Keyboard Privilege Escalation Vulnerability (2975685)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804472");
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2014-2781");
  script_bugtraq_id(68397);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-09 08:30:57 +0530 (Wed, 09 Jul 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Windows On-Screen Keyboard Privilege Escalation Vulnerability (2975685)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-039";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is triggered when executing the On-Screen keyboard from within the
context of a low integrity process.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain escalated
privileges.

Impact Level: System";

  tag_affected =
"Microsoft Windows 8 x32/x64
Windows 8.1 x32/x64 Edition
Microsoft Windows Server 2012/R2
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-039";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2973201");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2973906");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-039");
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

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath, file_name:"system32\win32k.sys");
if(!win32SysVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"6.0.6002.19119") ||
     version_in_range(version:win32SysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23419")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"6.1.7601.18512") ||
     version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22721")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"6.2.9200.17025")){
   security_message(0);
  }
  exit(0);
}

## Win 8.1
if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"6.2.9200.17025") ||
     version_in_range(version:win32SysVer, test_version:"6.2.9600.21000", test_version2:"6.2.9200.21141") ||
     version_in_range(version:win32SysVer, test_version:"6.3.9600.16000", test_version2:"6.3.9600.16670")){
    security_message(0);
  }
  exit(0);
}

## Win 2012R2
if(hotfix_check_sp(win2012R2:1) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"6.2.9200.17025")){
    security_message(0);
  }
  exit(0);
}
