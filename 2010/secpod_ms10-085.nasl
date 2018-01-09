###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-085.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Microsoft Windows SChannel Denial of Service Vulnerability (2207566)
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

tag_impact = "Successful exploits will allow attacker to execute arbitrary code in the
  context of the user running the application or cause a denial of service
  condition.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.
  Micorsoft Windows 7";
tag_insight = "The flaw is caused by an error in SChannel when processing client certificates
  in implementations of Internet Information Services, which could allow remote
  attackers to cause the LSASS service to stop responding and the system to
  restart by sending malformed packets to a server with SSL enabled.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-085.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-085.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901164");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3229");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows SChannel Denial of Service Vulnerability (2207566)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2207566");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2632");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-085.mspx");

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
if(hotfix_check_sp(winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## MS10-085 Hotfix (2207566)
if(hotfix_missing(name:"2207566") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\Schannel.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from Schannel.dll file
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:2, win2008:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    ## Check for Schannel.dll version
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18507")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Schannel.dll version
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18290")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  ## Check for Schannel.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16661")){
    security_message(0);
  }
}
