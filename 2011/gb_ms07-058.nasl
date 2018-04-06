###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms07-058.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vulnerability in RPC Could Allow Denial of Service (933729)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to send a specially
  crafted RPC authentication request to a computer over the network and cause
  the computer to stop responding and automatically restart.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows XP Service Pack 2 and prior
  Microsoft Windows 2000 ervice Pack 4 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista";
tag_insight = "The flaw is due to windows RPC code, that does not properly communicate
  with the 'NTLM' security provider when performing authentication of RPC requests.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms07-058.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS07-058.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801712");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2007-2228");
  script_bugtraq_id(25974);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Vulnerability in RPC Could Allow Denial of Service (933729)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/27134");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2007/Oct/1018787.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms07-058.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:3, win2003:3, winVista:3) <= 0){
  exit(0);
}

## Hotfix check
if(hotfix_missing(name:"933729") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath, file_name:"rpcrt4.dll");
  if(sysVer)
  {
    # Windows 2K
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Grep for rpcrt4.dll version < 5.0.2195.7090
      if(version_is_less(version:sysVer, test_version:"5.0.2195.7090")){
        security_message(0);
      }
    }
 
    ## Windows XP
    else if(hotfix_check_sp(xp:3) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        ## Grep for rpcrt4.dll version < 5.1.2600.3173
         if(version_is_less(version:sysVer, test_version:"5.1.2600.3173")){
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
      if("Service Pack 1" >< SP)
      {
        ## Grep for rpcrt4.dll version < 5.2.3790.2971
        if(version_is_less(version:sysVer, test_version:"5.2.3790.2971")){
          security_message(0);
        }
         exit(0);
      }
      if("Service Pack 2" >< SP)
      {
        ## Grep for rpcrt4.dll version < 5.2.3790.4115
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4115")){
          security_message(0);
        }
         exit(0);
      }
      security_message(0);
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath, file_name:"system32\rpcrt4.dll");
if(!sysVer){
  exit(0);
}
 
## Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  ## Grep for rpcrt4.dll version < 6.0.6000.16525
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16525")){
      security_message(0);
  }
  exit(0);
}
