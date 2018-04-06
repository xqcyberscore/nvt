###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-077.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2567053)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow local attackers to gain elevated
  privileges or to run arbitrary code in kernel mode and take complete control
  of an affected system. An attacker could then install programs view, change,
  or delete data or create new accounts with full administrative rights.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "Multiple flaws are due to,
  - A privilege elevation vulnerability exists in the way that kernel-mode
    drivers validate data supplied from user mode to kernel mode.
  - A denial of service vulnerability exists in implementations of windows
    when the system improperly processes a specially crafted TrueType font
    file.
  - An remote code execution vulnerability exists in the Windows kernel due
    to improper handling of a specially crafted font (.fon) file.
  - A privilege elevation vulnerability exists due to the way that Windows
    Kernel-mode drivers manage kernel-mode driver objects.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-077";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-077.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902483");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_bugtraq_id(49981, 49975, 49973, 49968);
  script_cve_id("CVE-2011-2011", "CVE-2011-2003", "CVE-2011-2002", "CVE-2011-1985");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2567053)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2567053");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-077");

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

## MS11-077 Hotfix (2567053)
if(hotfix_missing(name:"2567053") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Win32k.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Win32k.sys version before 5.1.2600.6149
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6149")){
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
    ## Check for Win32k.sys version before 5.2.3790.4905
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4905")){
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

  if("Service Pack 2" >< SP)
  {
    ## Check for Win32k.sys version
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18511")||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22710")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16877")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21045")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17684")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21810")){
    security_message(0);
  }
}
