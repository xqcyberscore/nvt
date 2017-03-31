###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-087.nasl 5588 2017-03-16 10:00:36Z teissa $
#
# Microsoft Windows Print Spooler Components Multiple Vulnerabilities (3170005)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808194");
  script_version("$Revision: 5588 $");
  script_cve_id("CVE-2016-3238", "CVE-2016-3239");
  script_bugtraq_id(91609, 91612);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-16 11:00:36 +0100 (Thu, 16 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-07-13 08:01:45 +0530 (Wed, 13 Jul 2016)");
  script_name("Microsoft Windows Print Spooler Components Multiple Vulnerabilities (3170005)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-087");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to
  - When the Windows Print Spooler service improperly allows arbitrary writing
    to the file system.
  - An improper validation of print drivers while installing a printer from
    servers.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code and take control of an affected system,
  also allows local users to gain privileges.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 for 32-bit/64-bit");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-087");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3170005");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-087");

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
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, winVistax64:3, win2008:3, win2008x64:3,
                   win2008r2:2, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Fetch the version of Win32spl.dll
sysVer = fetch_file_version(sysPath, file_name:"System32\Win32spl.dll");
if(!sysVer){
  exit(0);
}

if (sysVer =~ "^(6\.0\.6002\.1)"){
  Vulnerable_range = "Less than 6.0.6002.19666";
}
else if (sysVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23980";
}
else if (sysVer =~ "^(6\.1\.7601)"){
  Vulnerable_range = "Less than 6.1.7601.23488";
}
else if (sysVer =~ "^(6\.2\.9200)"){
  Vulnerable_range = "Less than 6.2.9200.21916";
}
else if (sysVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18398";
}
else if (sysVer =~ "^(10\.0\.10240)"){
  Vulnerable_range = "Less than 10.0.10240.17022";
}
else if (sysVer =~ "^(10\.0\.10586)"){
  Vulnerable_range = "10.0.10586.0 - 10.0.10586.493";
}

## Windows Vista and Server 2008
if(hotfix_check_sp(winVista:3, winVistax64:3, win2008x64:3, win2008:3) > 0)
{
  ## Check for Win32spl.dll version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.19666")||
     version_in_range(version:sysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23980")){
    VULN = TRUE ;
  }
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Presently GDR information is not available.
  ## Check for Win32spl.dll version
  if(version_is_less(version:sysVer, test_version:"6.1.7601.23488")){
    VULN = TRUE ;
  }
}

## Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Presently GDR information is not available. 
  ## Check for Win32spl.dll version
  if(version_is_less(version:sysVer, test_version:"6.2.9200.21916")){
     VULN = TRUE ;
  }
}

## Windows 8.1 and Server 2012 R2 
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Win32spl.dll version
  if(version_is_less(version:sysVer, test_version:"6.3.9600.18398")){
    VULN = TRUE ;
  }
}

## Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Windows 10
  ## Check for Win32spl.dll version
  if(version_is_less(version:sysVer, test_version:"10.0.10240.17022") ||
     version_in_range(version:sysVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.493")){
     VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\system32\Win32spl.dll" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
