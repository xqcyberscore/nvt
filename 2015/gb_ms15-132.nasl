###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-132.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Microsoft Windows Remote Code Execution Vulnerability (3116162)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806645");
  script_version("$Revision: 10017 $");
  script_cve_id("CVE-2015-6128", "CVE-2015-6132", "CVE-2015-6133");
  script_bugtraq_id(78612, 78614, 78615);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2015-12-09 09:32:19 +0530 (Wed, 09 Dec 2015)");
  script_name("Microsoft Windows Remote Code Execution Vulnerability (3116162)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-132.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"Flaw exists due to an error in the windows
  which improperly validates input before loading libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take complete control of an affected system.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 10 x32/x64

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 Version 1511 x32/x64

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,

  https://technet.microsoft.com/library/security/MS15-132");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3108371");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3108347");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3108381");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3108371");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-132");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath, file_name:"System32\Catsrvut.dll");
dllVer2 = fetch_file_version(sysPath, file_name:"System32\Authui.dll");
if(!dllVer && !dllVer2){
  exit(0);
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"2001.12.8531.19062"))
  {
    Vulnerable_range = "Less than 2001.12.8531.19062";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"2001.12.8531.23000", test_version2:"2001.12.8531.23277"))
  {
    Vulnerable_range = "2001.12.8531.23000 - 2001.12.8531.23277";
    VULN = TRUE ;
  }
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"2001.12.6932.19537"))
  {
    Vulnerable_range = "Less than 2001.12.6932.19537";
    VULN = TRUE ;
  }
  else if(version_in_range(version:dllVer, test_version:"2001.12.6932.23000", test_version2:"2001.12.6932.23846"))
  {
    Vulnerable_range = "2001.12.6932.23000 - 2001.12.6932.23846";
    VULN = TRUE ;
  }
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"2001.12.10130.17581"))
    {
      Vulnerable_range = "Less than 2001.12.10130.17581";
      VULN = TRUE ;
    }
    else if(version_in_range(version:dllVer, test_version:"2001.12.10130.21000", test_version2:"2001.12.10130.21702"))
    {
      Vulnerable_range = "2001.12.10130.21000 - 2001.12.10130.21702";
      VULN = TRUE ;
    }
  }

  if(dllVer2)
  {
    if(version_is_less(version:dllVer2, test_version:"6.2.9200.17561"))
    {
      Vulnerable_range1 = "Less than 6.2.9200.17561";
      VULN1 = TRUE ;
    }
    else if(version_in_range(version:dllVer2, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21677"))
    {
      Vulnerable_range1 = "6.2.9200.21000 - 6.2.9200.21677";
      VULN1 = TRUE ;
    }
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(dllVer && version_is_less(version:dllVer, test_version:"2001.12.10530.18146"))
  {
    Vulnerable_range = "Less than 2001.12.10530.18146";
    VULN = TRUE ;
  }
  if(dllVer2 && version_is_less(version:dllVer2, test_version:"6.3.9600.18111"))
  {
    Vulnerable_range1 = "Less than 6.3.9600.18111";
    VULN1 = TRUE ;
  }
}

## Windows 10
else if(hotfix_check_sp(win10:1, win10x64:1) > 0 && dllVer2)
{
  ## Windows 10 Core
  if(version_is_less(version:dllVer2, test_version:"10.0.10240.16603"))
  {
    Vulnerable_range = "Less than 10.0.10240.16603";
    VULN1 = TRUE ;
  }
  ## Windows 10 version 1511
  if(version_in_range(version:dllVer2, test_version:"10.0.10586.0", test_version2:"10.0.10586.19"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
    VULN1 = TRUE ;
  }
}


if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Catsrvut.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Authui.dll" + '\n' +
           'File version:     ' + dllVer2  + '\n' +
           'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
