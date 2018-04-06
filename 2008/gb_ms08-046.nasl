###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-046.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Microsoft Windows Image Color Management System Code Execution Vulnerability (952954)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_impact = "Successful exploitation could execute arbitrary code when a user opens a
  specially crafted image file and can gain same user rights as the local
  user. An attacker could then install programs; view, change, or delete
  data, or create new accounts.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K/XP/2003";
tag_insight = "The flaw is due to the way Microsoft Color Management System (MSCMS)
  module of the Microsoft ICM component handles memory allocation.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-049.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-046.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800023");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2245");
  script_bugtraq_id(30594);
  script_name("Microsoft Windows Image Color Management System Code Execution Vulnerability (952954)");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-046.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\Mscms.dll";

# Check for MS08-046 Hotfix (952954)
if(hotfix_missing(name:"952954") == 0){
  exit(0);
}

fileVer = get_version(dllPath:dllPath, string:"prod", offs:60000);
if(!fileVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  # Check for version < 5.0.2195.7162
  if(version_is_less(version:fileVer, test_version:"5.0.2195.7162")){
    security_message(0);
  }
  exit(0);
}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # < 5.1.2600.3396
    if(version_is_less(version:fileVer, test_version:"5.1.2600.3396")){
      security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Check for version < 5.1.2600.5627
    if(version_is_less(version:fileVer, test_version:"5.1.2600.5627")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Check for version < 5.2.3790.3163
    if(version_is_less(version:fileVer, test_version:"5.2.3790.3163")){
      security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 2" >< SP)
  {
    # Check for version < 5.2.3790.4320
    if(version_is_less(version:fileVer, test_version:"5.2.3790.4320")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
