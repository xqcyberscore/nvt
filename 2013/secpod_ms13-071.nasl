###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-071.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows Theme File Remote Code Execution Vulnerability (2864063)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.901221");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0810");
  script_bugtraq_id(62176);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-11 09:15:03 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Windows Theme File Remote Code Execution Vulnerability (2864063)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS13-071.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is caused when Microsoft Windows improperly handles theme and
screensaver files.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code and
take complete control of an affected system.

Impact Level: System";

  tag_affected =
"Microsoft Windows XP Service Pack 3 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows 2003 x32/x64 Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-071";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54736");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2864063");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-071");
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
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Themeui.dll file
sysVer = fetch_file_version(sysPath, file_name:"system32\Themeui.dll");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Themeui.dll version
  if(version_is_less(version:sysVer, test_version:"6.0.2900.6437")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Themeui.dll version
  if(version_is_less(version:sysVer, test_version:"6.0.3790.5211")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Themeui.dll version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18888") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23160")){
    security_message(0);
  }
  exit(0);
}
