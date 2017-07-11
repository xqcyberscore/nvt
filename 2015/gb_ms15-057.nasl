###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-057.nasl 6391 2017-06-21 09:59:48Z teissa $
#
# Microsoft Windows Media Player Remote Code Execution Vulnerability (3033890)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805649");
  script_version("$Revision: 6391 $");
  script_cve_id("CVE-2015-1728");
  script_bugtraq_id(75029);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-06-21 11:59:48 +0200 (Wed, 21 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-06-10 08:37:49 +0530 (Wed, 10 Jun 2015)");
  script_name("Microsoft Windows Media Player Remote Code Execution Vulnerability (3033890)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-057.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists as the an improper handling
  of DataObjects by the affected software.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  an unauthenticated, remote attacker to execute arbitrary code with the
  privileges of the user, which can compromise the application and possibly the
  system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Windows 2003 x32/x64 Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Service Pack 2 and prior
  Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS15-057");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/3033890");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-057");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win2008:3, win7:2,
                   win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath, file_name:"system32\wmp.dll");
if(!dllVer){
  exit(-1);
}

##Windows Server 2003
if(hotfix_check_sp(win2003x64:3,win2003:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:dllVer, test_version:"11.0.5721.5275") ||
     version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.4010")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:dllVer, test_version:"11.0.6002.19378") ||
     version_in_range(version:dllVer, test_version:"11.0.6002.23000", test_version2:"11.0.6002.23683")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:dllVer, test_version:"12.0.7601.18840") ||
     version_in_range(version:dllVer, test_version:"12.0.7601.22000", test_version2:"12.0.7601.23040")){
    security_message(0);
  }
  exit(0);
}

