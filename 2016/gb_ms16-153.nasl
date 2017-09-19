###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-153.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# MS Windows Common Log File System Driver Information Disclosure Vulnerability (3207328)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810310");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-7295");
  script_bugtraq_id(94787);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-12-14 09:20:01 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Windows Common Log File System Driver Information Disclosure Vulnerability (3207328)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-153.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw exists due to the Windows
  Common Log File System (CLFS) driver improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to run a specially crafted application to bypass security
  measures on the affected system allowing further exploitation.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows Server 2016 x64
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-0153");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3207328");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS16-153");
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
                   win10x64:1, win2016:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Fetch the version of 'Clfs.sys' and 'Edgehtml.dll'
clfVer = fetch_file_version(sysPath, file_name:"system32\drivers\clfs.sys");
clfVer1 = fetch_file_version(sysPath, file_name:"system32\clfs.sys");
edgeVer = fetch_file_version(sysPath, file_name:"system32\Edgehtml.dll");
if(!clfVer && !edgeVer && !clfVer1){
  exit(0);
}

## Windows 8.1 and Windows Server 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Clfs.sys version
  if(clfVer && version_is_less(version:clfVer, test_version:"6.3.9600.18539"))
  {
    Vulnerable_range = "Less than 6.3.9600.18539";
    VULN = TRUE ;
  }
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Clfs.sys version
  if(clfVer1 && version_is_less(version:clfVer1, test_version:"6.1.7601.23598"))
  {
    Vulnerable_range1 = "Less than 6.1.7601.23598";
    VULN1 = TRUE ;
  }
}

## Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Check for Clfs.sys version
  if(clfVer && version_is_less(version:clfVer, test_version:"6.2.9200.22034"))
  {
    Vulnerable_range = "Less than 6.2.9200.22034";
    VULN = TRUE ;
  }
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
{
  ## Check for Clfs.sys version
  if(clfVer1 && version_is_less(version:clfVer1, test_version:"6.0.6002.19717"))
  {
    Vulnerable_range1 = "Less than 6.0.6002.19717";
    VULN1 = TRUE ;
  }
  else if(clfVer1 && version_in_range(version:clfVer1, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24038"))
  {
    Vulnerable_range1 = "6.0.6002.23000 - 6.0.6002.24038";
    VULN1 = TRUE ;
  }
}

## Windows 10
else if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0 && edgeVer)
{
  ## Check for Edgehtml.dll version
  if(edgeVer && version_is_less(version:edgeVer, test_version:"11.0.10240.17202"))
  {
    Vulnerable_range1 = "Less than 11.0.10240.17202";
    VULN1 = TRUE ;
  }
  ## Windows 10 Version 1511
  else if(edgeVer && version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.712"))
  {
    Vulnerable_range1 = "11.0.10586.0 - 11.0.10586.712";
    VULN1 = TRUE ;
  }

  ## Windows 10 version 1607 and Windows Server 2016
  else if(edgeVer && version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.575"))
  {
    Vulnerable_range1 = "11.0.14393.0 - 11.0.14393.575";
    VULN1 = TRUE ;
  }

  if(VULN1)
  {
    report = 'File checked:     ' + sysPath + "\system32\Edgehtml.dll" + '\n' +
             'File version:     ' + edgeVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\drivers\Clfs.sys" + '\n' +
           'File version:     ' + clfVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Clfs.sys" + '\n' +
           'File version:     ' + clfVer1  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
