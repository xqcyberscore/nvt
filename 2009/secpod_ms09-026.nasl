###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-026.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Vulnerability in RPC Could Allow Elevation of Privilege (970238)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-01
#       - To detect file version 'Rpcrt4.dll' on vista and win 2008
#
# Copyright (c) 2009 SecPod, http://www.secpod.org
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900668");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-10 16:35:14 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0568");
  script_name("Vulnerability in RPC Could Allow Elevation of Privilege (970238)");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1545");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-026.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : "Successful exploitation could allow remote or local attackers to execute
  arbitrary code by sending specially crafted RPC message to a vulnerable
  third-party RPC application
  Impact Level: System");
  script_tag(name : "affected" , value : "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.");
  script_tag(name : "insight" , value : "The flaws occurs because the Remote Procedure Call (RPC) Marshalling Engine
  does not updating its internal state in an appropriate manner.");
  script_tag(name : "solution" , value : "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-026.mspx");
  script_tag(name : "summary" , value : "This host is missing a critical security update according to
  Microsoft Bulletin MS09-026.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# Check Hotfix Missing 970238 (MS09-026)
if(hotfix_missing(name:"970238") == 0){
  exit(0);
}

## Get System32 path
sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath, file_name:"Rpcrt4.dll");
  if(!sysVer){
      exit(0);
  }
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Rpcrt4.dll  version < 5.0.2195.7281
    if(version_is_less(version:sysVer, test_version:"5.0.2195.7281")){
      security_message(0);
  }
   exit(0);
}

# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll < 5.1.2600.3555
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3555")){
      security_message(0);
    }
     exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Rpcrt4.dll < 5.1.2600.5795
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5795")){
      security_message(0);
    }
      exit(0);
  }
  security_message(0);
}

# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 5.2.3790.4502
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4502")){
      security_message(0);
    }
      exit(0);
  }
  security_message(0);
}

## Get System32 path
sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath, file_name:"Rpcrt4.dll");
  if(!dllVer){
    exit(0);
  }
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Rpcrt4.dll version < 6.0.6001.18247
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
        security_message(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 6.0.6002.18024
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      security_message(0);
    }
     exit(0);
  }
  security_message(0);
}

# Windows Server 2008
else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Rpcrt4.dll version < 6.0.6001.18247
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
      security_message(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 6.0.6002.18024
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      security_message(0);
    }
    exit(0);
  }
 security_message(0);
}

