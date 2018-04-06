###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-019.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft File Handling Component Remote Code Execution Vulnerability (2922229)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804375");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-0315");
  script_bugtraq_id(66619);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-04-09 08:14:46 +0530 (Wed, 09 Apr 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft File Handling Component Remote Code Execution Vulnerability (2922229)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS14-019.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due to an improper path restrictions when processing .bat and .cmd
files related to the 'CreateProcess' function.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code and
potentially compromise user's system.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2
Microsoft Windows XP Service Pack 3 and prior
Microsoft Windows XP x64 Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows 2003 x32/x64 Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-019";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57642");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/91356");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2922229");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-019");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from 'kernel32.dll' file
sysVer = fetch_file_version(sysPath, file_name:"\system32\kernel32.dll");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for kernel32.dll version before 5.1.2600.6532
  if(version_is_less(version:sysVer, test_version:"5.1.2600.6532")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for kernel32.dll version before 5.2.3790.5295
  if(version_is_less(version:sysVer, test_version:"5.2.3790.5295")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for kernel32.dll version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.19034") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23322")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for kernel32.dll version
  if(version_is_less(version:sysVer, test_version:"6.1.7601.18409") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22615")){
    security_message(0);
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
 ## Check for kernel32.dll version
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16815") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20934")){
    security_message(0);
  }
  exit(0);
}

## Win 8.1
## Currently not supporting for Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
 ## Check for kernel32.dll version
  if(version_is_less(version:sysVer, test_version:"6.3.9600.16656")){
    security_message(0);
  }
  exit(0);
}
