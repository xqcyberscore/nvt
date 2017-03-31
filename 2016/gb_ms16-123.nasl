###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-123.nasl 5588 2017-03-16 10:00:36Z teissa $
#
# Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (3192892)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809343");
  script_version("$Revision: 5588 $");
  script_cve_id("CVE-2016-3266", "CVE-2016-3376", "CVE-2016-7185", "CVE-2016-7211",
                "CVE-2016-3341");
  script_bugtraq_id(93384, 93388, 93389, 93391);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-16 11:00:36 +0100 (Thu, 16 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-10-12 07:44:40 +0530 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (3192892)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-123.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and 
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  - The kernel-mode driver fails to properly handle objects in memory.
  - The Windows Transaction Manager improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  could run arbitrary code in kernel mode. An attacker could then install programs
  view, change, or delete data, or create new accounts with full user rights, and
  take control over the affected system.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/MS16-123");

  script_tag(name:"solution_type", value:"VendorFix");
  
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3192892");  
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-123");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Fetch the version of 'Win32k.sys'
win32Ver = fetch_file_version(sysPath, file_name:"System32\Win32k.sys");
mrxVer = fetch_file_version(sysPath, file_name:"System32\Drivers\Mrxdav.sys");
edgeVer = fetch_file_version(sysPath, file_name:"System32\Edgehtml.dll");
if(!win32Ver && !mrxVer && !edgeVer){
  exit(0);
}

##Windows 8.1 and Windows Server 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0 && win32Ver)
{
  ## Check for Win32k.sys version
  if(win32Ver && version_is_less(version:win32Ver, test_version:"6.3.9600.18470"))
  {
    Vulnerable_range = "Less than 6.3.9600.18470";
    VULN = TRUE ;
  }
}

##Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && win32Ver)
{
  ## Check for Win32k.sys version
  if(win32Ver && version_is_less(version:win32Ver, test_version:"6.1.7601.23545"))
  {
    Vulnerable_range = "Less than 6.1.7601.23545";
    VULN = TRUE ;
  }
}

##Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0 && win32Ver)
{
  ## Check for Win32k.sys version
  if(win32Ver && version_is_less(version:win32Ver, test_version:"6.2.9200.21977"))
  {
    Vulnerable_range = "Less than 6.2.9200.21977";
    VULN = TRUE ;
  }
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  ## Check for Win32k.sys version
  if(win32Ver && version_is_less(version:win32Ver, test_version:"6.0.6002.19693"))
  {
    Vulnerable_range = "Less than 6.0.6002.19693";
    VULN = TRUE ;
  }
  else if(win32Ver && version_in_range(version:win32Ver, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24016"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24016";
    VULN = TRUE ;
  }
  else if(mrxVer && version_is_less(version:mrxVer, test_version:"6.0.6002.19691"))
  {
    Vulnerable_range1 = "Less than 6.0.6002.19691";
    VULN1 = TRUE ;
  }
  else if(mrxVer && version_in_range(version:mrxVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24015"))
  {
    Vulnerable_range1 = "6.0.6002.23000 - 6.0.6002.24016";
    VULN1 = TRUE ;
  }
}

## Windows 10
else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && edgeVer)
{
  ## Check for edgehtml.dll version
  if(edgeVer && version_is_less(version:edgeVer, test_version:"11.0.10240.17146"))
  {
    Vulnerable_range2 = "Less than 11.0.10240.17146";
    VULN2 = TRUE ;
  }
  ## Windows 10 Version 1511
  else if(edgeVer && version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
  {
    Vulnerable_range2 = "11.0.10586.0 - 11.0.10586.632";
    VULN2 = TRUE ;
  }
  ## Windows 10 version 1607
  ## Check for edgehtml.dll version
  else if(edgeVer && version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
  {
    Vulnerable_range2 = "11.0.14393.0 - 11.0.14393.320";
    VULN2 = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Win32k.sys" + '\n' +
           'File version:     ' + win32Ver  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Drivers\Mrxdav.sys" + '\n' +
           'File version:     ' + mrxVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}

else if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range2 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
