###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-114.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Microsoft Windows Journal Remote Code Execution Vulnerability (3100213)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806554");
  script_version("$Revision: 10017 $");
  script_cve_id("CVE-2015-6097");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2015-11-11 08:24:04 +0530 (Wed, 11 Nov 2015)");
  script_name("Microsoft Windows Journal Remote Code Execution Vulnerability (3100213)");

  script_tag(name: "summary" , value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-114.");

  script_tag(name: "vuldetect" , value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name: "insight" , value:"The flaw is due to an unspecified error
  within Windows Journal while parsing Journal files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial-of-service attack or execute arbitrary code in the context
  of the currently logged-in user and compromise a user's system.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,

  https://technet.microsoft.com/library/security/ms15-114");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3100213");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms15-114");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"CommonFilesDir");
if(!sysPath){
  exit(0);
}

sysPath = sysPath + "\Microsoft Shared\ink";

dllVer = fetch_file_version(sysPath, file_name:"Journal.dll");
if(!dllVer){
  exit(0);
}

if (dllVer =~ "^(6\.1\.7601\.1)"){
  Vulnerable_range = "Less than 6.1.7601.19021";
}
else if (dllVer =~ "^(6\.1\.7601\.2)"){
  Vulnerable_range = "6.1.7601.23000 - 6.1.7601.23225";
}
else if (dllVer =~ "^(6\.0\.6002\.2)"){
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23816";
}
else if (dllVer =~ "^(6\.0\.6002\.1)"){
  Vulnerable_range = "Less than 6.0.6002.19507";
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.6002.19507") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23816")){
    VULN = TRUE ;
  }
}

## Windows 7 and Windows Server 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.19021") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.23000", test_version2:"6.1.7601.23225")){
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\Journal.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
