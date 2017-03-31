###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-044.nasl 58149 2016-04-13 08:06:29 +0530 April$
#
# Microsoft Windows OLE Remote Code Execution Vulnerability (3146706)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807789");
  script_version("$Revision: 5580 $");
  script_cve_id("CVE-2016-0153");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-15 11:00:34 +0100 (Wed, 15 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-13 08:06:29 +0530 (Wed, 13 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows OLE Remote Code Execution Vulnerability (3146706)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-044.");

  script_tag(name: "vuldetect" , value: "Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value: "The flaw is due to Microsoft Windows OLE
  fails to properly validate user input.");

  script_tag(name: "impact" , value: "Successful exploitation will allow attackers
  to execute malicious code.

  Impact Level: System");
  
  script_tag(name: "affected" , value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows Server 2012 and Server 2012R2.");

  script_tag(name: "solution" , value: "Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-044");

  script_tag(name:"solution_type", value:"VendorFix");
 
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3146706");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/2919355");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS16-044");

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
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8_1:1, win8_1x64:1, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from 'Ole32' file
dllVer = fetch_file_version(sysPath, file_name:"system32\Ole32.dll");
if(!dllVer){
  exit(0);
}

if (dllVer =~ "^(6\.0\.6002\.1)"){
  Vulnerable_range = "Less than 6.0.6002.19623";
}
else if (dllVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23935";
}
else if (dllVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18256";
}
else if (dllVer =~ "^(6\.2\.9200\.2)"){
  Vulnerable_range = "Less than 6.2.9200.21792 ";
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Ole32.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19623") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23935")){
    VULN=TRUE;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Ole32.dll version
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18256")){
    VULN=TRUE;
  }
}

## Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Check for Ole32.dll version
  if(version_is_less(version:dllVer, test_version:"6.2.9200.21792")){
    VULN=TRUE;
  }
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Ole32.dll version

  if(version_is_less(version:dllVer, test_version:"6.1.7601.23392")){
    Vulnerable_range = "Less than 6.1.7601.23392";
    VULN=TRUE;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Ole32.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
