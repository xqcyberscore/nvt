###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-037.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Windows MHTML Information Disclosure Vulnerability (2544893)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2011-11-09
#   - Updated versions based on Revision V2.0
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

tag_impact = "Successful exploitation could allow attackers to gain knowledge of sensitive
  information.
  Impact Level: Application";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is caused by an error in the way MHTML (MIME Encapsulation of Aggregate
  HTML) interprets MIME-formatted requests for content blocks within a document,
  which could allow attackers to inject a client-side script in the response of a
  web request run in the context of Internet Explorer by tricking a user into
  following a specially crafted 'MHTML:' link.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-037.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-037.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902441");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-1894");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Windows MHTML Information Disclosure Vulnerability (2544893)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2544893");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS11-037.mspx");

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

## MS11-037 Hotfix 2544893
if((hotfix_missing(name:"2544893") == 0)){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Inetcomm.dll
sysVer = fetch_file_version(sysPath, file_name:"system32\Inetcomm.dll");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Inetcomm.dll
    if(version_is_less(version:sysVer, test_version:"6.0.2900.6157")){
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
    ## Check for Inetcomm.dll version
    if(version_is_less(version:sysVer, test_version:"6.0.3790.4913")){
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
    ## Check for Inetcomm.dll version
    if(version_in_range(version:sysVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18644")||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22910")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Inetcomm.dll version
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18462")||
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
  ## Check for Inetcomm.dll version
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16807")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20957")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17608")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21718")){
    security_message(0);
  }
}
