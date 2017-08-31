###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-071.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Microsoft Window Audio Service Privilege Escalation Vulnerability (3005607)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804880");
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-6322");
  script_bugtraq_id(70978);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-12 10:30:01 +0530 (Wed, 12 Nov 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Window Audio Service Privilege Escalation Vulnerability (3005607)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-071.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw is due to an error within the
  Windows Audio Service.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker
  to execute arbitrary scripts with elevated privileges.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows 8 x32/x64
  Microsoft Windows 8.1 x32/x64 Edition
  Microsoft Windows Server 2012/R2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS14-071");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59968");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/3005607");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS14-071");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
dllVer="";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1,
                   win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath, file_name:"system32\Audiosrv.dll");
if(!dllVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Audiosrv.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19201") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23505")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Audiosrv.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18619") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22825")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  ## Check for Audiosrv.dll version
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17134") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21250")){
    security_message(0);
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Audiosrv.dll version
  if(version_is_less(version:dllVer, test_version:"6.3.9600.17393")){
    security_message(0);
  }
  exit(0);
}
