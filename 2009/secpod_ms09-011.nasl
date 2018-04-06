###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-011.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft DirectShow Remote Code Execution Vulnerability (961373)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation on remote vulnerable system allow arbitrary code
  execution and can potentially compromise a user's system.
  Impact Level: System";
tag_affected = "DirectX 8.1 and 9.0 on Microsoft Windows 2000
  DirectX 9.0 on Microsoft Windows XP and 2003";
tag_insight = "DirectX application throws an an error when decompressing MJPEG content,
  and can be exploited via a specially crafted MJPEG file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-011.mspx";
tag_summary = "This host has critical security update missing according to
  Microsoft Bulletin MS09-011.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900093");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-15 18:21:29 +0200 (Wed, 15 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0084");
  script_bugtraq_id(34460);
  script_name("Microsoft DirectShow Remote Code Execution Vulnerability (961373)");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-011.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod"); 
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

# OS with Hotfix Check
if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check DirectX is installed
directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
if(!egrep(pattern:"^4\.0[89]\..*", string:directXver)){
  exit(0);
}

# MS09-011 Hotfix check
if(hotfix_missing(name:"961373") == 0){
  exit(0);
}

dllFile = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllFile){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllFile);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllFile + "\quartz.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(directXver =~ "^4\.08")
  {
    # Grep Quartz.dll version < 6.3.1.892
    if(version_is_less(version:dllVer, test_version:"6.3.1.892")){
      security_message(0);
    }
  }
  else if(directXver =~ "^4\.09")
  {
    # Grep Quartz.dll version < 6.5.1.910
    if(version_is_less(version:dllVer, test_version:"6.5.1.910")){
      security_message(0);
    }
  }
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(directXver =~ "^4\.09")
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      # Grep Quartz.dll version < 6.5.2600.3497
      if(version_is_less(version:dllVer, test_version:"6.5.2600.3497")){
        security_message(0);
      }
    }
    else if("Service Pack 3" >< SP)
    {
      # Grep Quartz.dll version < 6.5.2600.5731
      if(version_is_less(version:dllVer, test_version:"6.5.2600.5731")){
        security_message(0);
      }
    }
  }
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(directXver =~ "^4\.09")
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep Quartz.dll version < 6.5.3790.3266
      if(version_is_less(version:dllVer, test_version:"6.5.3790.3266")){
        security_message(0);
      }
    }
    else if("Service Pack 2" >< SP)
    {
      # Grep Quartz.dll version < 6.5.3790.4431
      if(version_is_less(version:dllVer, test_version:"6.5.3790.4431")){
        security_message(0);
      }
    }
  }
}
