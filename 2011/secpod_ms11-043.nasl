###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-043.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft SMB Client Remote Code Execution Vulnerabilities (2536276)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-08-11
# - Updated the version check according to the bulletin
#   release V2.0 (August 9, 2011)
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

tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary code
  by creating a specially crafted SMB responses.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior
  Microsoft Windows Server 2008 Service Pack 1/2 and prior";
tag_insight = "The flaws are due to errors in SMB client implementation which fails to
  validate specially crafted SMB responses.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS11-043.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-043.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900287");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_bugtraq_id(48184);
  script_cve_id("CVE-2011-1268");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft SMB Client Remote Code Execution Vulnerabilities (2536276)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44898/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2536276");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS11-043.mspx");

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

## MS11-043 Hotfix (2536276)
if(hotfix_missing(name:"2536276") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Mrxsmb.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\Mrxsmb.sys");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Mrxsmb.sys version < 5.1.2600.6133
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6133")){
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
    ## Check for Mrxsmb.sys version < 5.2.3790.4883
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4883")){
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

  if("Service Pack 1" >< SP)
  {
    ## Check for Mrxsmb.sys version
    if(version_in_range(version:sysVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18643")||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22909")){
      security_message(0);
    }
    exit(0);
  }
  if("Service Pack 2" >< SP)
  {
    ## Check for Mrxsmb.sys version
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18461")||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22633")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Mrxsmb.sys version
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16807")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20958")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17604")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21713")){
    security_message(0);
  }
}
