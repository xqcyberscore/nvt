##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-063_900053.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: SMB Remote Code Execution Vulnerability (957095)
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

tag_impact = "Successful exploitation could allow remote attackers to cause
  a buffer underflow.
  Impact Level: System/Network";
tag_affected = "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.";
tag_insight = "The issue is due to an input validation error in the handling of
  file names in the Microsoft SMB (Server Message Block) protocol.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-063.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-063.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900053");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31647);
  script_cve_id("CVE-2008-4038");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("SMB Remote Code Execution Vulnerability (957095)");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-063.mspx");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-001.mspx");

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
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check Hotfix Missing 958687 (MS09-001)
if(hotfix_missing(name:"958687") == 0){
  exit(0);
}

# Check Hotfix Missing 957095 (MS08-063)
if(hotfix_missing(name:"957095") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\drivers\Srv.sys");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Srv.sys version < 5.0.2195.7177
  if(egrep(pattern:"^5\.0\.2195\.([0-6]?[0-9]?[0-9]?[0-9]|7(0[0-9][0-9]|" +
                   "1[0-6][0-9]|17[0-6]))$", string:sysVer)){
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
    # Grep for Srv.sys < 5.1.2600.3436
    if(egrep(pattern:"^5\.1\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-3][0-9][0-9]|" +
                     "4([0-2][0-9]|3[0-5])))$", string:sysVer)){
       security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Srv.sys < 5.1.2600.5671
    if(egrep(pattern:"^5\.1\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9][0-9]|" +
                     "6([0-6][0-9]|70)))$", string:sysVer)){
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
    # Grep for Srv.sys version < 5.2.3790.3200
    if(egrep(pattern:"^5\.2\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3[01][0-9][0-9])$",
             string:sysVer)){
       security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 2" >< SP)
  {
    # Grep for Srv.sys version < 5.2.3790.4363
    if(egrep(pattern:"^5\.2\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|" +
                     "3([0-5][0-9]|6[0-2])))$", string:sysVer)){
       security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
