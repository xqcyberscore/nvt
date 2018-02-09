###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-024.nasl 8724 2018-02-08 15:02:56Z cfischer $
#
# Windows Fax Cover Page Editor Remote Code Execution Vulnerability (2527308)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu sanadi <santu@secpod.com> on 2011-05-18
#  - Updated null check for versions
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to gain the same user rights as
  the logged-on user. Users whose accounts are configured to have fewer user
  rights on the system could be less impacted than users who operate with
  administrative user rights.

  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2K3 Service Pack 2 and prior

  Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to error in fax cover page editor, when user opened a
  specially crafted fax cover page file (.cov) using the windows fax cover page
  editor will trigger a memory corruption error in the Fax Cover Page Editor
  (fxscover.exe) and execute arbitrary code on the target system.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  http://www.microsoft.com/technet/security/bulletin/ms11-024.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-024.";

if(description)
{
  script_id(902408);
  script_version("$Revision: 8724 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 16:02:56 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2010-3974");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Windows Fax Cover Page Editor Remote Code Execution Vulnerability (2527308)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2491683");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2506212");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-024.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-024 Hotfix (2491683) and (2506212)
if((hotfix_missing(name:"2491683") == 0) && (hotfix_missing(name:"2506212") == 0)){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Win32k.sys version and Mfc42.dll
sysVer1 = fetch_file_version(sysPath, file_name:"system32\fxscover.exe");
sysVer2 = fetch_file_version(sysPath, file_name:"system32\Mfc42.dll");
if( ! sysVer1 && ! sysVer2 ) exit( 0 );

## Avoid passing FALSE values to the version_* functions later if fetch_file_version() returns FALSE
if( ! sysVer1 ) sysVer1 = "unknown";
if( ! sysVer2 ) sysVer2 = "unknown";

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Win32k.sys and Mfc42.dll version
    if(version_is_less(version:sysVer1, test_version:"5.2.2600.6078") ||
       version_is_less(version:sysVer2, test_version:"6.2.8081.0")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Check for Win32k.sys and Mfc42.dll version
    if(version_is_less(version:sysVer1, test_version:"5.2.3790.4829") ||
       version_is_less(version:sysVer2, test_version:"6.6.8064.0")){
      security_message(0);
    }
   exit(0);
  }
  security_message(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    ## Check for Win32k.sys and Mfc42.dll version
    if(version_in_range(version:sysVer1, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18596")||
       version_in_range(version:sysVer1, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22851") ||
       version_is_less(version:sysVer2, test_version:"6.6.8064.0")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Win32k.sys and Mfc42.dll version
    if(version_in_range(version:sysVer1, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18402")||
       version_in_range(version:sysVer1, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22585") ||
       version_is_less(version:sysVer2, test_version:"6.6.8064.0")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Win32k.sys and Mfc42.dll version
  if(version_is_less(version:sysVer1, test_version:"6.1.7600.16759")||
     version_is_less(version:sysVer2, test_version:"6.6.8064.0") ||
     version_in_range(version:sysVer1, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20899")||
     version_in_range(version:sysVer1, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17558")||
     version_in_range(version:sysVer1, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21658")){
    security_message(0);
  }
}
