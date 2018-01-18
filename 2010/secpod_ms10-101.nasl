###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-101.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Microsoft Windows Netlogon Service Denial of Service Vulnerability (2207559)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allows attackers to cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Windows Server 2003 Service Pack 2 and prior.
  Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The issue is caused by an error in the Netlogon RPC Service when processing
  user-supplied data, which could allow attackers to crash an affected server
  that is configured as a domain controller.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-101.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-101.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902277");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_cve_id("CVE-2010-2742");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows Netlogon Service Denial of Service Vulnerability (2207559)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2305420");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-101.mspx");

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
if(hotfix_check_sp(win2003:3, win2008:3) <= 0){
  exit(0);
}

## MS10-101 Hotfix (2207559)
if(hotfix_missing(name:"2207559") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\Netlogon.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from Schannel.dll file
sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

## Windows Server 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
     ## Grep for Netlogon.dll version < 5.2.3790.4760
     if(version_is_less(version:sysVer, test_version:"5.2.3790.4760")){
        security_message(0);
     }
     exit(0);
  }
  security_message(0);
}

## Windows Server 2008
if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");

  if("Service Pack 1" >< SP)
  {
    ## Grep for Netlogon.dll version < 6.0.6001.18529
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18529")){
      security_message(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Grep for Netlogon.dll version < 6.0.6002.18316
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18316")){
      security_message(0);
    }
     exit(0);
  }
   security_message(0);
}
