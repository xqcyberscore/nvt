###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-028.nasl 6391 2017-06-21 09:59:48Z teissa $
#
# Microsoft Windows Task Scheduler security Feature Bypass Vulnerability (3030377)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805144");
  script_version("$Revision: 6391 $");
  script_cve_id("CVE-2015-0084");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-21 11:59:48 +0200 (Wed, 21 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-03-11 10:27:42 +0530 (Wed, 11 Mar 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Task Scheduler security Feature Bypass Vulnerability (3030377)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-028.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists as Windows Task Scheduler
  fails to properly validate and enforce impersonation levels.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to gain elevated privileges.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows 8 x32/x64
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/R2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the given link, https://technet.microsoft.com/library/security/MS15-028");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/3030377");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-028");

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

## Variables Initialization
sysPath = "";
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(-1);
}

dllVer = fetch_file_version(sysPath, file_name:"system32\Ubpm.dll");
if(!dllVer){
  exit(-1);
}

if (dllVer =~ "^(6\.1\.7601\.2)"){
  Vulnerable_range = "6.1.7601.22000 - 6.1.7601.22947";
}
else if (dllVer =~ "^(6\.1\.7601\.)"){
  Vulnerable_range = "Less than 6.1.7601.18741";
}
else if (dllVer =~ "^(6\.2\.9200\.2)"){
  Vulnerable_range = "6.2.9200.20000 - 6.2.9200.21363";
}
else if (dllVer =~ "^(6\.2\.9200\.)"){
  Vulnerable_range = "Less than 6.2.9200.17247";
}
else if (dllVer =~ "^(6\.3\.9600\.)"){
  Vulnerable_range = "Less than 6.3.9600.17671";
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Ubpm.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18741") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22947")){
    VULN = TRUE ;
  }
}

## Windows 8 x86, Windows 8 x64 and Windows Server 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  ## Check for Ubpm.dll version
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17247") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21363")){
    VULN = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Ubpm.dll version
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17671")){
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Ubpm.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
