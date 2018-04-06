###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-099.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2618444)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
  code in the context of the application. Failed exploit attempts will result
  in denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x";
tag_insight = "Multiple flaws are due to the way Internet Explorer handles,
  - the XSS filter,
  - loading of external libraries ie .DLL files and
  - the content settings supplied by the Web server.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-099";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-099.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902642");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-1992", "CVE-2011-2019", "CVE-2011-3404");
  script_bugtraq_id(50974, 50975, 50976);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-14 09:25:00 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2618444)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2618444");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-099");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);

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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!(ieVer =~ "^(6|7|8|9)")){
  exit(0);
}

## MS11-099 Hotfix
if(hotfix_missing(name:"2618444") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Mshtml.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Mshtml.dll version
    if(version_in_range(version:dllVer, test_version:"6.0.2900.0000", test_version2:"6.0.2900.6168") ||
       version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17106")||
       version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21308")||
       version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19169") ||
       version_in_range(version:dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23265")){
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
    ## Check for Mshtml.dll version
    if(version_in_range(version:dllVer, test_version:"6.0.3790.0000", test_version2:"6.0.3790.4928") ||
       version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17106")||
       version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21308")||
       version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19169") ||
       version_in_range(version:dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23265")){
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
    ## Check for Mshtml.dll version
    if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18537")||
       version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22738")||
       version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19169")||
       version_in_range(version:dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23265")||
       version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16439")||
       version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20543")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16911")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.21084")||
     version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.17719")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.21854")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16439")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20543")){
    security_message(0);
  }
}
