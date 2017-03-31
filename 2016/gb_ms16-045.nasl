###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms16-045.nasl 5513 2017-03-08 10:00:24Z teissa $
#
# Microsoft Windows Hyper-V Multiple Vulnerabilities (3143118)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807661");
  script_version("$Revision: 5513 $");
  script_cve_id("CVE-2016-0088", "CVE-2016-0089", "CVE-2016-0090");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-08 11:00:24 +0100 (Wed, 08 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-13 08:09:15 +0530 (Wed, 13 Apr 2016)");
  script_name("Microsoft Windows Hyper-V Multiple Vulnerabilities (3143118)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-045");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  when Windows Hyper-V on a host operating system fails to properly validate 
  input from an authenticated user on a guest operating system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  execute arbitrary code on the host operating system, also could gain access to
  information on the Hyper-V host operating system.  

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 8.1 x64 Edition
  Microsoft Windows Server 2012/2012R2
  Microsoft Windows 10 x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-045");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3143118");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-045");

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
sysPath1 = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2012:1, win2012R2:1, win8_1x64:1, win10x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath1 = smb_get_systemroot();
if(!sysPath1){
  exit(0);
}

##Fetch the version of Vmsif.dll
sysVer = fetch_file_version(sysPath:sysPath1, file_name:"System32\Vmsif.dll");
if(!sysVer){
  exit(0);
}

if (sysVer =~ "^(6\.3\.9600\.1)"){
  Vulnerable_range = "Less than 6.3.9600.18258";
}
else if (sysVer =~ "^(10\.0\.10240)"){
  Vulnerable_range = "Less than 10.0.10240.16766";
}


## Windows Server 2012
#if(hotfix_check_sp(win2012:1) > 0)
#{
   #Vmswitch.sys file has dynamic path.
#}

## Windows 8.1 and Server 2012 R2 
else if(hotfix_check_sp(win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Vmsif.dll version
  if(version_is_less(version:sysVer, test_version:"6.3.9600.18258")){
    VULN = TRUE ;
  }
}

## Windows 10
if(hotfix_check_sp(win10x64:1) > 0)
{
  ## Windows 10
  ## Check for Vmsif.dll version
  if(version_is_less(version:sysVer, test_version:"10.0.10240.16725")){
     VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath1 + "\system32\Vmsif.dll" + '\n' +
           'File version:     ' + sysVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
