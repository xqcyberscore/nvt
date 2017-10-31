###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-061.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# MS Windows Remote Privilege Escalation Vulnerability (3155520)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807587");
  script_version("$Revision: 7582 $");
  script_cve_id("CVE-2016-0178");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-05-11 08:26:35 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS Windows Remote Privilege Escalation Vulnerability (3155520)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-061.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists due to when windows improperly
  handles specially crafted Remote Procedure Call (RPC) requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code with elevated privileges.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 10 x32/x64
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 Version 1511 x32/x64
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-061");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/3153171");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-061");

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
shelldllPath = "";
shelldllVer = 0;

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2, win2012:1, 
                   win2012R2:1, win8_1:1, win8_1x64:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Fetch the version of Ntoskrnl.exe
ntexeVer = fetch_file_version(sysPath, file_name:"System32\Ntoskrnl.exe");
##Fetch the version of Rpcrt4.dll
rpdllVer = fetch_file_version(sysPath, file_name:"system32\Rpcrt4.dll");

if(!ntexeVer && !rpdllVer){
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{

  if(ntexeVer)
  {
    ## Check for 'Ntoskrnl.exe' file  version
    if(version_is_less(version:ntexeVer, test_version:"6.3.9600.18289"))
    {
      Vulnerable_range = "Less than 6.3.9600.18289";
      VULN1 = TRUE ;
    }
  }

  ## Check for 'Rpcrt4.dll' file  version
  else if(rpdllVer)
  {
    if(version_is_less(version:rpdllVer, test_version:"6.3.9600.18292"))
    {
      Vulnerable_range = "Less than 6.3.9600.18292";
      VULN2 = TRUE ;
    }
  }
}

## Windows 2012
else if(hotfix_check_sp(win2012:1) > 0)
{
  ## Check for 'Ntoskrnl.exe' file  version
  if(ntexeVer &&  version_is_less(version:ntexeVer, test_version:"6.2.9200.21830"))
  {
    Vulnerable_range = "Less than 6.2.9200.21830";
    VULN1 = TRUE ;
  }

  ## Check for 'Rpcrt4.dll' file  version
  else if(rpdllVer && version_is_less(version:rpdllVer, test_version:"6.2.9200.21826"))
  {
    Vulnerable_range = "Less than 6.2.9200.21826";
    VULN2 = TRUE ;
  }
}

## Windows Vista and Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Ntoskrnl.exe version
  if(ntexeVer && version_is_less(version:ntexeVer, test_version:"6.0.6002.19636"))
  {
    Vulnerable_range = "Less than 6.0.6002.19636";
    VULN1 = TRUE ;
  }
  else if(ntexeVer && version_in_range(version:ntexeVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23949"))
  {
    Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23949";
    VULN1 = TRUE ;
  }
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Ntoskrnl.exe version
  if(ntexeVer && version_is_less(version:ntexeVer, test_version:"6.1.7601.23418"))
  {
    Vulnerable_range = "Less than 6.1.7601.23418";
    VULN1 = TRUE ;
  }
}

## Windows 10
if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  ## Check for Ntoskrnl.exe version
  ## Windows 10
  if(version_is_less(version:ntexeVer, test_version:"10.0.10240.16841"))
  {
    Vulnerable_range = "Less than 10.0.10240.16841";
    VULN1 = TRUE;
  }

  ## Windows 10 Version 1511
  else if(version_in_range(version:ntexeVer, test_version:"10.0.10586.0", test_version2:"10.0.10586.305"))
  {
    VULN1 = TRUE;
    Vulnerable_range = "10.0.10586.0 - 10.0.10586.305";
  }
}


if(VULN1)
{
  report = 'File checked:     ' + sysPath + "\System32\Ntoskrnl.exe" + '\n' +
           'File version:     ' + ntexeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

if(VULN2)
{
  report = 'File checked:     ' + sysPath + "\System32\Rpcrt4.dll" + '\n' +
           'File version:     ' + rpdllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

