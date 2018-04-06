###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-078.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2783534)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code with kernel-mode privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "- An error in the OpenType Font (OTF) driver when handling certain objects
    can be exploited via a specially crafted font file.
  - An error when handling certain TrueType Fonts (TTF) can be exploited
    via a specially crafted font file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-078";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-078.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902936");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2556", "CVE-2012-4786");
  script_bugtraq_id(56842, 56841);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-12 09:08:07 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Windows Kernel-Mode Drivers Remote Code Execution Vulnerabilities (2783534)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51459/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2753842");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2779030");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-078");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
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

## Variables Initialization
sysPath = "";
winsVer = "";
afdVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Win32k.sys file
winsVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");
afdVer = fetch_file_version(sysPath, file_name:"system32\Atmfd.dll");

if(winsVer || afdVer)
{
  ## Windows XP
  if(hotfix_check_sp(xp:4) > 0)
  {
    ## Check for Win32k.sys version before 5.1.2600.6322
    ## Check for Atmfd.dll version before 5.1.2.24
    if(version_is_less(version:winsVer, test_version:"5.1.2600.6322") ||
       version_is_less(version:afdVer, test_version:"5.1.2.235")){
      security_message(0);
    }
    exit(0);
  }

  ## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
  else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
  {

    ## Check for Win32k.sys version before 5.2.3790.5094
    ## Check for Atmfd.dll version before 5.2.2.234
    if(version_is_less(version:winsVer, test_version:"5.2.3790.5094") ||
       version_is_less(version:afdVer, test_version:"5.2.2.235")){
      security_message(0);
    }
    exit(0);
  }

  ## Windows Vista and Windows Server 2008
  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    ## Check for Win32k.sys and Atmfd.dll version
    if(version_is_less(version:winsVer, test_version:"6.0.6002.18733") ||
       version_in_range(version:winsVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22976") ||
       version_is_less(version:afdVer, test_version:"5.1.2.235")){
      security_message(0);
    }
    exit(0);
  }

  ## Windows 7
  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    ## Check for Win32k.sys and Atmfd.dll version
    if(version_is_less(version:winsVer, test_version:"6.1.7600.17174") ||
       version_in_range(version:winsVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21378")||
       version_in_range(version:winsVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18008")||
       version_in_range(version:winsVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22170") ||
       version_is_less(version:afdVer, test_version:"5.1.2.237")){
      security_message(0);
    }
  }
}
