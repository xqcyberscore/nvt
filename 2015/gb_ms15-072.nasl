###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-072.nasl 6333 2017-06-14 10:00:49Z teissa $
#
# Microsoft Windows Graphics Component Privilege Elevation Vulnerability (3069392)
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
  script_oid("1.3.6.1.4.1.25623.1.0.805920");
  script_version("$Revision: 6333 $");
  script_cve_id("CVE-2015-2364");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-14 12:00:49 +0200 (Wed, 14 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-07-15 11:06:14 +0530 (Wed, 15 Jul 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Graphics Component Privilege Elevation Vulnerability (3069392)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-072.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists due to error when windows
  graphics component fails to properly process bitmap conversions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows 8 x32/x64
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows Server 2012 R2
  Microsoft Windows 7 x32/x64 Edition Service Pack 1
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2
  Microsoft Windows Vista x32/x64 Edition Service Pack 2
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/en-us/library/security/MS15-072");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3069392");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS15-072");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


##Code Starts from here

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
dllVer="";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2,  win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

##Get file version of 'Gdi32.dll'
dllVer = fetch_file_version(sysPath, file_name:"system32\Gdi32.dll");
if(!dllVer){
  exit(0);
}

##Windows Server 2003
if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  ## Check for Gdi32.dll version
  if(version_is_less(version:dllVer, test_version:"5.2.3790.5661")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Gdi32.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19421")||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23727")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Gdi32.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18898") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23099")){
    security_message(0);
  }
  exit(0);
}

## Windows 8, and Windows Server 2012
if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Check for Gdi32.dll version
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17410")||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21520")){
    security_message(0);
  }
  exit(0);
}

## Windows 8.1, Windows 2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Gdi32.dll version
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17902")){
    security_message(0);
  }
  exit(0);
}
