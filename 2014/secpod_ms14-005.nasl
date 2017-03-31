###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms14-005.nasl 5346 2017-02-19 08:43:11Z cfi $
#
# Microsoft Window XML Core Services Information Disclosure Vulnerability (2916036)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903510";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5346 $");
  script_cve_id("CVE-2014-0266");
  script_bugtraq_id(65407);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-19 09:43:11 +0100 (Sun, 19 Feb 2017) $");
  script_tag(name:"creation_date", value:"2014-02-12 08:44:58 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft Window XML Core Services Information Disclosure Vulnerability (2916036)");

   tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS14-005.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an unspecified error which improperly enforce cross-domain
policies.";

  tag_impact =
"Successful exploitation will allow remote attackers to read files on the
local file system of the user or read content of web domains where the user
is currently authenticated.

Impact Level: System/Application ";

  tag_affected =
"Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2
Microsoft Windows XP Service Pack 3 and prior
Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows 2003 x32/x64 Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior ";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-005";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56771");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2916036");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-005");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

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
if(!sysPath ){
  exit(0);
}

## Get Version from Msxml3.dll file
sysVer = fetch_file_version(sysPath, file_name:"system32\Msxml3.dll");
if(!sysVer){
  exit(0);
}

## Windows XP,Windows XP x64,Windows 2003 x86 and Windows 2003 x64
if(hotfix_check_sp(xp:4, win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Msxml3.dll version
  if(version_is_less(version:sysVer, test_version:"8.100.1054.0")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Msxml3.dll version
  if(version_is_less(version:sysVer, test_version:"8.100.5007.0")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Msxml3.dll version
  if(version_is_less(version:sysVer, test_version:"8.110.7601.18334") ||
     version_in_range(version:sysVer, test_version:"8.110.7601.22000", test_version2:"8.110.7601.22531")){
    security_message(0);
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
 ## Check for Msxml3.dll version
  if(version_is_less(version:sysVer, test_version:"8.110.9200.16772") ||
     version_in_range(version:sysVer, test_version:"8.110.9200.20000", test_version2:"8.110.9200.20889")){
    security_message(0);
  }
  exit(0);
}

## Win 8.1
## Currently not supporting for Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
 ## Check for Msxml3.dll version
  if(version_is_less(version:sysVer, test_version:"8.110.9600.16483")){
    security_message(0);
  }
  exit(0);
}
