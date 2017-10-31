###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4034681.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# Microsoft Windows Multiple Vulnerabilities (KB4034681)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811280");
  script_version("$Revision: 7585 $");
  script_cve_id("CVE-2017-0174", "CVE-2017-0250", "CVE-2017-0293", "CVE-2017-8591", 
                "CVE-2017-8593", "CVE-2017-8620", "CVE-2017-8624", "CVE-2017-8633", 
                "CVE-2017-8635", "CVE-2017-8636", "CVE-2017-8641", "CVE-2017-8653", 
                "CVE-2017-8664", "CVE-2017-8666", "CVE-2017-8668", "CVE-2017-8669");
  script_bugtraq_id(100038, 98100, 100039, 99430, 100032, 100034, 100061, 100069,
                    100055, 100056, 100057, 100059, 100085, 100089, 100092, 100068);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-08-09 09:06:54 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4034681)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034681");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,
  
  - An error in Windows when the Win32k component fails to properly handle
    objects in memory. 
  - An error in Windows Input Method Editor (IME) when IME improperly handles
    parameters in a method of a DCOM class. 
  - An error when Microsoft browsers improperly access objects in memory. 
  - An error in Windows Error Reporting (WER). 
  - An error in the way JavaScript engines render when handling objects in
    memory in Microsoft browsers. 
  - An error when Windows Hyper-V on a host server fails to properly validate
    input from an authenticated user on a guest operating system. 
  - An error in the Microsoft JET Database Engine that could allow remote code
    execution on an affected system. 
  - An error when Windows Search handles objects in memory. 
  - An error in the way that Microsoft browser JavaScript engines render content
    when handling objects in memory. 
  - An error when Microsoft Windows PDF Library improperly handles objects in
    memory. 
  - An error when Microsoft Windows improperly handles NetBIOS packets. 
  - An error when the win32k component improperly provides kernel information. 
  - An error when the Volume Manager Extension Driver component improperly provides 
    kernel information.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to run arbitrary code in kernel mode, gain the same user rights as
  the current user, access to sensitive information and system functionality
  and conduct a denial-of-service condition.

  Impact Level: System");

  script_tag(name:"affected", value:"
  Microsoft Windows Server 2012 R2

  Microsoft Windows 8.1 for 32-bit/x64");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4034681");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4034681");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
fileVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

##Fetch the version of 'tdx.sys'
fileVer = fetch_file_version(sysPath, file_name:"Drivers\tdx.sys");
if(!fileVer){
  exit(0);
}

## Check for tdx.sys version
if(version_is_less(version:fileVer, test_version:"6.3.9600.18783"))
{
  report = 'File checked:     ' + sysPath + "\Drivers\tdx.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.3.9600.18783\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
