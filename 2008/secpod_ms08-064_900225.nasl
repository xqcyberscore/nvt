##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-064_900225.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Virtual Address Descriptor Manipulation Elevation of Privilege Vulnerability (956841)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900225");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31675);
  script_cve_id("CVE-2008-4036");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Virtual Address Descriptor Manipulation Elevation of Privilege Vulnerability (956841)");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : "Successful exploitation could allow elevation of privilege and can
  cause a memory allocation mapping error and corrupt memory on affected system.
  Impact Level: System");
  script_tag(name : "affected" , value : "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows Server 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows Server 2008 Service Pack 1 and prior.");
  script_tag(name : "insight" , value : "The flaw exists due to the way that Memory Manager handles memory allocation
  and Virtual Address Descriptors (VADs).");
  script_tag(name : "summary" , value : "This host is missing important security update according to
  Microsoft Bulletin MS08-064.");
  script_tag(name : "solution" , value : "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/Bulletin/MS08-064.mspx");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS08-064.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");



if(hotfix_check_sp(xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

# Check for Hotfix 956841 (MS08-064).
if(hotfix_missing(name:"956841") == 0){
  exit(0);
}

## Get System32 path
sysPath = smb_get_system32root();
if(sysPath)
{
  fileVer = fetch_file_version(sysPath, file_name:"Ntoskrnl.exe");
  if(fileVer)
  {
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
     	# Grep Ntoskrnl.exe version < 5.1.2600.3427
    	if(egrep(pattern:"^5\.1\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-3][0-9]" +
                     "[0-9]|4([01][0-9]|2[0-6])))$", string:fileVer)){
      	  security_message(0);
    	}
    	exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Grep Ntoskrnl.exe version < 5.1.2600.5657
        if(egrep(pattern:"^5\.1\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9]" +
                     "[0-9]|6([0-4][0-9]|5[0-6])))$", string:fileVer)){
          security_message(0);
        }
        exit(0);
      }
      security_message(0);
    }

    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep Ntoskrnl.exe version < 5.2.3790.3191
        if(egrep(pattern:"^5\.2\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3(0[0-9][0-9]" +
                     "|1([0-8][0-9]|90)))$", string:fileVer)){
          security_message(0);
        }
        exit(0);
      }
      else if("Service Pack 2" >< SP)
      {
        # Grep Ntoskrnl.exe version < 5.2.3790.4354
        if(egrep(pattern:"^5\.2\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9]" +
                     "[0-9]|3([0-4][0-9]|5[0-3])))$", string:fileVer)){
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
  exeVer = fetch_file_version(sysPath, file_name:"ntoskrnl.exe");
  if(exeVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Ntoskrnl.exe version < 6.0.6001.18145
        if(version_is_less(version:exeVer, test_version:"6.0.6001.18145")){
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
        # Grep for Ntoskrnl.exe version < 6.0.6001.18145
        if(version_is_less(version:exeVer, test_version:"6.0.6001.18145")){
          security_message(0);
        }
         exit(0);
      }
    }
  }
}
