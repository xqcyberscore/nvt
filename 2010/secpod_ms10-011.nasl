###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-011.nasl 9122 2018-03-17 14:01:04Z cfischer $
#
# Microsoft Client/Server Run-time Subsystem Privilege Elevation Vulnerability (978037)
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

tag_impact = "Successful exploitation could allow remote attackers to monitor all actions
  performed by other logged-in users or run arbitrary code in kernel mode.

  Impact Level: System";
tag_affected = "Microsoft Windows 2000 Service Pack 4 and prior

  Microsoft Windows XP Service Pack 3 and prior

  Microsoft Windows 2003 Service Pack 2 and prior";
tag_insight = "The issue is caused by an error in the 'Client/Server Run-time Subsystem' (CSRSS)
  that does not properly terminate user processes when a user logs out.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-011.mspx";
tag_summary = "This host is missing a critical security update according to Microsoft
  Bulletin MS10-011.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902116");
  script_version("$Revision: 9122 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-17 15:01:04 +0100 (Sat, 17 Mar 2018) $");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0023");
  script_bugtraq_id(38098);
  script_name("Microsoft Client/Server Run-time Subsystem Privilege Elevation Vulnerability (978037)");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0344");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-011.mspx");

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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check for MS10-011 Hotfix Missing 978037
if(hotfix_missing(name:"978037") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Csrsrv.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Csrsrv.dll version < 5.0.2195.7366
  if(version_is_less(version:sysVer, test_version:"5.0.2195.7366")){
    security_message(0);
  }
}
# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Csrsrv.dll < 5.1.2600.3657
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3657")){
      security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Csrsrv.dll <  5.1.2600.5915
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5915")){
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
    # Grep for Csrsrv.dll version <  5.2.3790.4635
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4635")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
