###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-075.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# Microsoft Active Accessibility Remote Code Execution Vulnerability (2623699)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  code in the context of the user running the vulnerable application.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to a way that the Microsoft Active Accessibility
  component handles the loading of DLL files. This can be exploited to load
  arbitrary libraries by tricking a user into opening a file located on a
  remote WebDAV or SMB share.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-075";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-075.";

if(description)
{
  script_id(902746);
  script_version("$Revision: 7582 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)");
  script_cve_id("CVE-2011-1247");
  script_bugtraq_id(49976);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Active Accessibility Remote Code Execution Vulnerability (2623699)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46403/");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-075");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
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

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-075 Hotfix 2564958
if((hotfix_missing(name:"2564958") == 0)){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version for Oleacc.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\Oleacc.dll");
if(dllVer)
{
  ## Windows XP
  if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 3" >< SP)
    {
      ## Check for Oleacc.dll version
      if(version_is_less(version:dllVer, test_version:"7.0.2600.6153")){
        security_message(0);
      }
      exit(0);
    }
    security_message(0);
  }

  ## Windows 2003
  else if(hotfix_check_sp(win2003:3) > 0)
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 2" >< SP)
    {
      ## Check for Oleacc.dll version
      if(version_is_less(version:dllVer, test_version:"7.0.3790.4909")){
        security_message(0);
      }
      exit(0);
    }
    security_message(0);
  }

  ## Windows Vista and Windows Server 2008
  else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");

    if(!SP) {
      SP = get_kb_item("SMB/Win2008/ServicePack");
    }

    if("Service Pack 2" >< SP)
    {
      ## Check for Oleacc.dll version
      if(version_is_less(version:dllVer, test_version:"7.0.6002.18508")||
         version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22705")){
        security_message(0);
      }
      exit(0);
    }
    security_message(0);
  }
}

## Windows 7
## Get Version for Oleaut32.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\Oleaut32.dll");
if(dllVer)
{
  if(hotfix_check_sp(win7:2) > 0)
  {
    ## Check for Oleaut32.dll version
    if(version_is_less(version:dllVer, test_version:"6.1.7600.16872") ||
       version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21035") ||
       version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17675") ||
       version_in_range(version:dllVer, test_version:"6.1.7601.20000", test_version2:"6.1.7601.21801")){
        security_message(0);
    }
  }
}
