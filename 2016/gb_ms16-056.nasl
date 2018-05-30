###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-056.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Microsoft Windows Journal Memory Corruption Vulnerability (3156761)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808019");
  script_version("$Revision: 10017 $");
  script_cve_id("CVE-2016-0182");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2016-05-11 10:37:53 +0530 (Wed, 11 May 2016)");
  script_name("Microsoft Windows Journal Memory Corruption Vulnerability (3156761)");

  script_tag(name: "summary" , value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-056.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw is due to an unspecified error
  within Windows Journal while parsing Journal files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial-of-service attack or execute arbitrary code in the context
  of the currently logged-in user and compromise a user's system.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows 10 x32/x64

  Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,

  https://technet.microsoft.com/library/security/MS16-056");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3156761");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-056");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win8_1:1, win8_1x64:1, win2008:3,
                   win10:1, win10x64:1, win2012R2:1, win2012:1, win2008r2:2) <= 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"ProgramFilesDir");
if(!sysPath){
  exit(0);
}

sysPath = sysPath + "\Windows Journal";

dllVer = fetch_file_version(sysPath, file_name:"Inkseg.dll");
if(!dllVer){
  exit(0);
}

if (dllVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18294";
}
else if (dllVer =~ "^(6\.1\.7601\.2)"){
  Vulnerable_range = "Less than 6.1.7601.23415";
}
else if (dllVer =~ "^(6\.0\.6002\.19634)"){
  Vulnerable_range = "Less than 6.0.6002.19634";
}
else if (dllVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23947";
}

##Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.23415")){
    VULN = TRUE ;
  }
}

##Windows 8.1 and Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.3.9600.18294")){
    VULN = TRUE ;
  }
}
## Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.21830")){
     Vulnerable_range = "Less than 6.2.9200.21830";
     VULN = TRUE ;
  }
}

##Windows Vista and Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19634") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23947")){
    VULN = TRUE ;
  }
}

##Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Windows 10 Core
  if(version_is_less(version:dllVer, test_version:"10.0.10240.16683"))
  {
    Vulnerable_range = "Less than 10.0.10240.16683";
    VULN = TRUE ;
  }
  ## Windows 10 version 1511
  else if(version_in_range(version:dllVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.121"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.121";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Inkseg.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
