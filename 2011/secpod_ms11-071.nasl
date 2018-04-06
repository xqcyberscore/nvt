###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-071.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Components Remote Code Execution Vulnerabilities (2570947)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary
  code by enticing an unsuspecting victim to open a file on a remote SMB or
  WebDAV share.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaw exists when specific Windows components incorrectly restrict the
  path used for loading external libraries. An attacker can exploit this
  issue by enticing an unsuspecting victim to open a file on a remote SMB
  or WebDAV share.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-071";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-071.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901205");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_bugtraq_id(47741);
  script_cve_id("CVE-2011-1991");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Components Remote Code Execution Vulnerabilities (2570947)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2570947");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-071");

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
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

res = hotfix_missing(name:"2570947");

## MS11-071 Hotfix (2570947)
if(res == 0){
  exit(0);
}

## For XP and 2003 only registry changes
if((hotfix_check_sp(xp:4, win2003:3) == 1) && res == 1)
{
  security_message(0);
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Imjpapi.dll files version
sysVer = fetch_file_version(sysPath:sysPath,
                            file_name:"\System32\IME\IMEJP10\Imjpapi.dll");
if(!sysVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Imjpapi.dll version
    if(version_in_range(version:sysVer, test_version:"10.0.6002.18000", test_version2:"10.0.6002.18494")||
       version_in_range(version:sysVer, test_version:"10.0.6002.22000", test_version2:"10.0.6002.22683")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  ## Check for Imjpapi.dll version
  if(version_in_range(version:sysVer, test_version:"10.1.7600.16000", test_version2:"10.1.7600.16855")||
     version_in_range(version:sysVer, test_version:"10.1.7600.20000", test_version2:"10.1.7600.21015")||
     version_in_range(version:sysVer, test_version:"10.1.7601.17000", test_version2:"10.1.7601.17657")||
     version_in_range(version:sysVer, test_version:"10.1.7601.21000", test_version2:"10.1.7601.21778")){
    security_message(0);
  }
}
