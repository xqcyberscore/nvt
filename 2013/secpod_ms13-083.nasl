###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-083.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Comctl32 Integer Overflow Vulnerability (2864058)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903225");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3195");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-10-09 08:59:40 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Comctl32 Integer Overflow Vulnerability (2864058)");

  tag_summary =
"This host is missing an critical security update according to Microsoft
Bulletin MS13-083.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"A flaw exist in Comctl32.dll file which is caused by an integer overflow in
the common control library.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code on the
system with elevated privileges.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 8
Microsoft Windows Server 2012
Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2003 x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 R2 for x64 Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-083";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55106");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87402");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-083");
  script_xref(name : "URL" , value : "http://support.microsoft.com/default.aspx?scid=kb;EN-US;2864058");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
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
if(hotfix_check_sp(xpx64:3, win2003:3, win2003x64:3, winVista:3, winVistax64:3,
                   win7:2, win7x64:2, win2008:3, win2008x64:3, win2008r2:2,
                   win8:1, win8x64:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Comctl32.dll file
sysVer = fetch_file_version(sysPath, file_name:"system32\Comctl32.dll");
if(!sysVer){
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Comctl32.dll version
  if(version_is_less(version:sysVer, test_version:"5.82.3790.5190")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Comctl32.dll version
  if(version_is_less(version:sysVer, test_version:"5.82.6002.18879") ||
     version_in_range(version:sysVer, test_version:"5.82.6002.23000", test_version2:"5.82.6002.23150")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Comctl32.dll version
  if(version_is_less(version:sysVer, test_version:"5.82.7601.18201") ||
     version_in_range(version:sysVer, test_version:"5.82.7601.22000", test_version2:"5.82.7601.22375")){
    security_message(0);
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
 ## Check for Comctl32.dll version
  if(version_is_less(version:sysVer, test_version:"5.82.9200.16657") ||
     version_in_range(version:sysVer, test_version:"5.82.9200.20000", test_version2:"5.82.9200.20764")){
    security_message(0);
  }
  exit(0);
}
