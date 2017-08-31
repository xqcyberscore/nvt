###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-130.nasl 6453 2017-06-28 09:59:05Z teissa $
#
# Microsoft Windows Uniscribe Remote Code Execution Vulnerability (3108670)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806172");
  script_version("$Revision: 6453 $");
  script_cve_id("CVE-2015-6130");
  script_bugtraq_id(78500);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-28 11:59:05 +0200 (Wed, 28 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-12-09 09:39:22 +0530 (Wed, 09 Dec 2015)");
  script_name("Microsoft Windows Uniscribe Remote Code Execution Vulnerability (3108670)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-130.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when Windows Uniscribe
  improperly parses specially crafted fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS15-130");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-130");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3108670#bookmark-fileinfo");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(-1);
}

## Get Version from Usp10.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\Usp10.dll");
if(dllVer)
{
  if (dllVer =~ "^(1\.626\.7601\.1)"){
    Vulnerable_range = "1.626.7601.18000 - 1.626.7601.19053";
   }
  else if (dllVer =~ "^(1\.626\.7601\.2)"){
    Vulnerable_range = "1.626.7601.22000 - 1.626.7601.23258";
  }
}

## Windows 7 and Server 2008r2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Usp10.dll version
  if(version_in_range(version:dllVer, test_version:"1.626.7601.18000", test_version2:"1.626.7601.19053")||
     version_in_range(version:dllVer, test_version:"1.626.7601.22000", test_version2:"1.626.7601.23258"))
  {
    report = 'File checked:     ' + sysPath + "\system32\Usp10.dll" + '\n' +
             'File version:     ' + dllVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
