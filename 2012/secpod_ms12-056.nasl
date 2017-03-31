###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-056.nasl 5346 2017-02-19 08:43:11Z cfi $
#
# Microsoft JScript and VBScript Engines Remote Code Execution Vulnerability (2706045)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the current user.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 x64 Edition Service Pack 1 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 2003 x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";
tag_insight = "The flaw is caused by an integer overflow error in the JScript and VBScript
  scripting engines when calculating the size of an object in memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-056";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-056.";

if(description)
{
  script_id(903037);
  script_version("$Revision: 5346 $");
  script_cve_id("CVE-2012-2523");
  script_bugtraq_id(54945);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-19 09:43:11 +0100 (Sun, 19 Feb 2017) $");
  script_tag(name:"creation_date", value:"2012-08-15 11:13:45 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft JScript and VBScript Engines Remote Code Execution Vulnerability (2706045)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50243/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2706045");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-056");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
dllPath = "";
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xpx64:3, win2003x64:3, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
dllPath = smb_get_systemroot();
if(!dllPath ){
  exit(0);
}

## Get Version from Vbscript.dll file
dllVer = fetch_file_version(sysPath:dllPath, file_name:"System32\Vbscript.dll");
if(!dllVer){
  exit(0);
}

## Windows XP x64 and Windows 2003 x64
if(hotfix_check_sp(xpx64:3, win2003x64:3) > 0)
{
  ## Check for Vbscript.dll version
  if(version_is_less(version:dllVer, test_version:"5.8.6001.23380")){
    security_message(0);
  }
  exit(0);
}

## Currently not supporting for Vista and Windows Server 2008 64 bit

## Windows 7
else if(hotfix_check_sp(win7x64:2, win2008r2:2) > 0)
{
  ## Check for Vbscript.dll version
  if(version_is_less(version:dllVer, test_version:"5.8.7600.17045") ||
     version_in_range(version:dllVer, test_version:"5.8.7600.20000", test_version2:"5.8.7600.21237")||
     version_in_range(version:dllVer, test_version:"5.8.7601.17000", test_version2:"5.8.7601.17865")||
     version_in_range(version:dllVer, test_version:"5.8.7601.21000", test_version2:"5.8.7601.22023")){
    security_message(0);
  }
}

