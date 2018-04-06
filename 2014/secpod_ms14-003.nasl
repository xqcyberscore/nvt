###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms14-003.nasl 34348 2014-01-15 08:49:46Z jan$
#
# Microsoft Windows Kernel-Mode Drivers Privilege Escalation Vulnerability (2913602)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903424");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-0262");
  script_bugtraq_id(64725);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-01-15 08:05:29 +0530 (Wed, 15 Jan 2014)");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Escalation Vulnerability (2913602)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-003";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to the improper use of window handle thread-owned objects
in memory. This may allow local attacker to gain elevated privileges.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain escalated
privileges.

Impact Level: System";

  tag_affected =
"Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-003";


   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "vuldetect" , value : tag_vuldetect);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name:"qod_type", value:"registry");
   script_tag(name:"solution_type", value:"VendorFix");

   script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2913602");
   script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-003");
   script_category(ACT_GATHER_INFO);
   script_copyright("Copyright (C) 2014 SecPod");
   script_family("Windows : Microsoft Bulletins");
   script_dependencies("smb_reg_service_pack.nasl");
   script_mandatory_keys("SMB/WindowsVersion");
   exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
win32SysVer="";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath, file_name:"system32\win32k.sys");
if(!win32SysVer){
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Win32k.sys version
  if(version_is_less(version:win32SysVer, test_version:"6.1.7601.18327") ||
     version_in_range(version:win32SysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22524")){
    security_message(0);
  }
  exit(0);
}
