###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-140.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Microsoft Boot Manager Security Feature Bypass Vulnerability (3193479)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809802");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-7247");
  script_bugtraq_id(94058);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-11-09 08:16:52 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Boot Manager Security Feature Bypass Vulnerability (3193479)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-140.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw exists due to windows secure boot
  improperly loads a boot policy that is affected by the vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to disable code integrity checks, allowing test-signed executables
  and drivers to be loaded onto a target device.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x32/x64
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-140");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3193479");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS16-140");

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
if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1:1, win8_1x64:1, win10:1,
                   win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Fetch the version of 'Ole32.dll'
oleVer = fetch_file_version(sysPath, file_name:"System32\Ole32.dll");
if(!oleVer){
  exit(0);
}

## Windows 8.1 and Windows Server 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Ole32.dll version
  if(version_is_less(version:oleVer, test_version:"6.3.9600.18508"))
  {
    Vulnerable_range = "Less than 6.3.9600.18508";
    VULN = TRUE ;
  }
}

## Windows Server 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Check for Ole32.dll version
  if(version_is_less(version:oleVer, test_version:"6.2.9200.22005"))
  {
    Vulnerable_range = "Less than 6.2.9200.22005";
    VULN = TRUE ;
  }
}

## Windows 10
else if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Check for Ole32.dll version
  if(version_is_less(version:oleVer, test_version:"10.0.10240.17184"))
  {
    Vulnerable_range = "Less than 10.0.10240.17184";
    VULN = TRUE ;
  }
  ## Windows 10 Version 1511
  else if(version_in_range(version:oleVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.671"))
  {
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.671";
    VULN = TRUE ;
  }
  ## Windows 10 version 1607
  else if(version_in_range(version:oleVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.446"))
  {
    Vulnerable_range = "10.0.14393.0 - 10.0.14393.446";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\System32\Ole32.dll" + '\n' +
           'File version:     ' + oleVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
