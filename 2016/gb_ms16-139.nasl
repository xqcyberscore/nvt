###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-139.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Microsoft Windows Kernel Elevation of Privilege Vulnerability (3199720)
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809467");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-7216");
  script_bugtraq_id(94048);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-11-09 10:39:43 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Kernel Elevation of Privilege Vulnerability (3199720)");

  script_tag(name: "summary" , value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-139.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw exists in the way that the Windows
  Kernel API enforces permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  could gain access to information that is not intended for the user.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/MS16-139");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3199720");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-139");

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
kerPath = "";
kerVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, winVistax64:3, win2008:3, win2008x64:3,
                   win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
kerPath = smb_get_systemroot();
if(!kerPath ){
  exit(0);
}

##Fetch the version of Ntoskrnl.exe
kerVer = fetch_file_version(sysPath: kerPath, file_name:"System32\Ntoskrnl.exe");
if(!kerVer){
  exit(0);
}

if (kerVer =~ "^(6\.0\.6002\.1)"){
  Vulnerable_range = "Less than 6.0.6002.19700";
}
else if (kerVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24023";
}
else if (kerVer =~ "^(6\.1\.7601)"){
  Vulnerable_range = "Less than 6.1.7601.23569";
}

## Windows Vista and Server 2008
if(hotfix_check_sp(winVista:3, winVistax64:3, win2008x64:3, win2008:3) > 0)
{
  ## Check for Ntoskrnl.exe version
  if(version_is_less(version:kerVer, test_version:"6.0.6002.19700")||
     version_in_range(version:kerVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24023")){
    VULN = TRUE ;
  }
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Presently GDR information is not available.
  ## Check for Ntoskrnl.exe version
  if(version_is_less(version:kerVer, test_version:"6.1.7601.23569")){
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + kerPath + "\system32\Ntoskrnl.exe" + '\n' +
           'File version:     ' + kerVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
