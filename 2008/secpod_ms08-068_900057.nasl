##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-068_900057.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: SMB Could Allow Remote Code Execution Vulnerability (957097)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900057");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-12 16:32:06 +0100 (Wed, 12 Nov 2008)");
  script_bugtraq_id(7385);
  script_cve_id("CVE-2008-4037");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("SMB Could Allow Remote Code Execution Vulnerability (957097)");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-068.mspx");

  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : "Successful exploitation could allow attacker to replay the user's
  credentials back to them and execute code in the context of the logged-on
  user. They can get complete control of an affected system to view, change,
  or delete data or creating new accounts with full user rights.
  complete control of an affected system.

  Impact Level: System");

  script_tag(name : "affected" , value : "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows 2008 Server Service Pack 1 and prior.");

  script_tag(name : "insight" , value : "Issue exists due to the way that Server Message Block (SMB) Protocol handles
  NTLM credentials when a user connects to an attacker's SMB server.");

  script_tag(name : "solution" , value : "Run Windows Update and update the listed hotfixes or download
  and update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-068.mspx");

  script_tag(name : "summary" , value : "This host is missing a critical security update according to
  Microsoft Bulletin MS08-068.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

# Check Hotfix Missing 957097 (MS08-068)
if(hotfix_missing(name:"957097") == 0){
  exit(0);
}

## Get System32 path
sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath, file_name:"drivers\Mrxsmb.sys");
  if(sysVer)
  {
    # Windows 2K
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Grep for Srv.sys version < 5.0.2195.7174
      if(egrep(pattern:"^5\.0\.2195\.([0-6]?[0-9]?[0-9]?[0-9]|7([0][0-9][0-9]|" +
                   "16[0-9]|17[0-3]))$", string:sysVer)){
       security_message(0);
      }
       exit(0);
    }

    # Windows XP
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Grep for Srv.sys < 5.1.2600.3467
        if(egrep(pattern:"^5\.1\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-3][0-9][0-9]|" +
                     "4([0-5][0-9]|6[0-6])))$", string:sysVer)){
          security_message(0);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Grep for Srv.sys < 5.1.2600.5700
        if(egrep(pattern:"^5\.1\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9][0-9]|" +
                     "6([0-8][0-9]|9[0-9])))$", string:sysVer)){
          security_message(0);
        }
        exit(0);
      }
      security_message(0);
    }

    # Windows 2003
    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Srv.sys version < 5.2.3790.3206
        if(egrep(pattern:"^5\.2\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3[01][0-9][0-9]|" +
                     "32([0][0-5]))$",
             string:sysVer)){
           security_message(0);
        }
        exit(0);
      }
      else if("Service Pack 2" >< SP)
      {
        # Grep for Srv.sys version < 5.2.3790.4369
        if(egrep(pattern:"^5\.2\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|" +
                     "3([0-5][0-9]|6[0-8])))$", string:sysVer)){
          security_message(0);
        }
        exit(0);
      }
      security_message(0);
    }
  }
}

## Get System32 path
sysPath = smb_get_system32root();
if(sysPath)
{
  sysVer = fetch_file_version(sysPath, file_name:"drivers\Mrxsmb10.sys");
  if(sysVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Mrxsmb10.sys version < 6.0.6001.18130
        if(version_is_less(version:sysVer, test_version:"6.0.6001.18130")){
          security_message(0);
        }
         exit(0);
      }
    }

    # Windows Server 2008
    else if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Mrxsmb10.sys version < 6.0.6001.18130
        if(version_is_less(version:sysVer, test_version:"6.0.6001.18130")){
          security_message(0);
        }
         exit(0);
      }
    }
  }
}

