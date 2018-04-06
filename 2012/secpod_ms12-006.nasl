###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-006.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows SSL/TLS Information Disclosure Vulnerability (2643584)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
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

tag_impact = "Successful exploitation of this issue may allow attackers to perform limited
  man-in-the-middle attacks to inject data into the beginning of the
  application protocol stream to execute HTTP transactions, bypass
  authentication.
  Impact Level: Windows";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "A flaw exists is due to an error in Microsoft Windows SChannel (Secure Channel),
  when modifying the way that the Windows Secure Channel (SChannel) component
  sends and receives encrypted network packets.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-006";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-006.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902900");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-3389");
  script_bugtraq_id(49778);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-11 09:47:46 +0530 (Wed, 11 Jan 2012)");
  script_name("Microsoft Windows SSL/TLS Information Disclosure Vulnerability (2643584)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2585542");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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


if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  ## Check for Hotfix 2638806 (MS12-006)
  if(hotfix_missing(name:"2585542") == 1)
  {
    sysVer = fetch_file_version(sysPath, file_name:"system32\Schannel.dll");
    if(sysVer)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        ## Check for Schannel.dll version < 5.2.3790.4935
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4935")){
          security_message(0);
        }
        exit(0);
      }
      security_message(0);
    }
  }
  else if(hotfix_missing(name:"2638806") == 1)
  {
    security_message(0);
  }
  exit(0);
}

## Check for Hotfix 2585542 (MS12-006)
if(hotfix_missing(name:"2585542") == 0){
  exit(0);
}

## Get Version from  file Schannel.dll
sysVer = fetch_file_version(sysPath, file_name:"system32\Schannel.dll");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Schannel.dll version < 5.1.2600.6175
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6175")){
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
  if(!SP){
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Schannel.dll version
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18540")||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22741")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Grep for Schannel.dll version
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16915") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.21000", test_version2:"6.1.7600.21091") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17724") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21860")){
    security_message(0);
  }
}
