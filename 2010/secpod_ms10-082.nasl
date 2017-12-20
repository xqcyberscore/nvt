###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-082.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# Microsoft Windows Media Player Remote Code Execution Vulnerability (2378111)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application, which can compromise the
  application and possibly the system.
  Impact Level: System/Application";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows Media Player 10
  Microsoft Windows Media Player 11
  Microsoft Windows Media Player 12
  Microsoft Windows Media Player 9 Series
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaw is caused by a memory corruption error in Windows Media Player when
  deallocating objects during a reload operation via a web browser, which could
  allow attackers to execute arbitrary code by convincing a user to visit a
  specially crafted web page.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-082.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-082.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901163");
  script_version("$Revision: 8168 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-2745");
  script_bugtraq_id(43772);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Media Player Remote Code Execution Vulnerability (2378111))");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2378111");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2629");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-082.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## MS10-082 Hotfix (2378111)
if(hotfix_missing(name:"2378111") == 0){
  exit(0);
}

## Check Hotfix Missing for Media player
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\wmp.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from wmp.dll file
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for wmp.dll version
    if(version_in_range(version:dllVer, test_version:"9", test_version2:"9.0.0.4509") ||
       version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.4080")||
       version_in_range(version:dllVer, test_version:"11", test_version2:"11.0.5721.5279")){
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
    ## Check for wmp.dll version
    if(version_in_range(version:dllVer, test_version:"10", test_version2:"10.0.0.4007")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:2, win2008:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    ## Check for wmp.dll version
    if(version_in_range(version:dllVer, test_version:"11", test_version2:"11.0.6001.7009")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for wmp.dll version 11.0.6002.18311
    if(version_in_range(version:dllVer, test_version:"11", test_version2:"11.0.6002.18310")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  ## Check for wmp.dll version
  if(version_in_range(version:dllVer, test_version:"12", test_version2:"12.0.7600.16666")){
    security_message(0);
  }
}
