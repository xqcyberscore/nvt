###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-041.nasl 5363 2017-02-20 13:07:22Z cfi $
#
# Vulnerability in Workstation Service Could Allow Elevation of Privilege (971657)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-29
#     - To detect file version 'wkssvc.dll' on vista and win 2008
#
# Copyright:
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges, and can cause Denial of Service.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows XP  Service Pack 3 and prior
  Microsoft Windows 2k3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaw is due to a double free error while processing arguments
  passed to the 'NetrGetJoinInformation()' function. This can be exploited to
  trigger a memory corruption via a specially crafted RPC request.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-041.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-041.";

if(description)
{
  script_id(101102);
  script_version("$Revision: 5363 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 14:07:22 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1544");
  script_bugtraq_id(35972);
  script_name("Vulnerability in Workstation Service Could Allow Elevation of Privilege (971657)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36220/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/971657");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2236");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-041.mspx");

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

## This function will return the version of the given file
function get_file_version(sysPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\" + file_name);

  sysVer = GetVer(file:file, share:share);
  if(!sysVer){
    return(FALSE);
  }

  return(sysVer);
}

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"971657") == 0){
   exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  wkssvcVer = get_file_version(sysPath, file_name:"wkssvc.dll");
  if(!wkssvcVer){
     exit(0);
  }
}

# Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for wkssvc.dll < 5.1.2600.3584
    if(version_is_less(version:wkssvcVer, test_version:"5.1.2600.3584")){
      security_message(0);
    }
     exit(0);
  }
  if("Service Pack 3" >< SP)
  {
    # Grep for wkssvc.dll < 5.1.2600.5826
    if(version_is_less(version:wkssvcVer, test_version:"5.1.2600.5826")){
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
    # Grep for wkssvc.dll version < 5.2.3790.4530
    if(version_is_less(version:wkssvcVer, test_version:"5.2.3790.4530")){
      security_message(0);
    }
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"System32\wkssvc.dll");
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
    # Grep for wkssvc.dll version < 6.0.6001.18270
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18270")){
      security_message(0);
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for wkssvc.dll version < 6.0.6002.18049
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18049")){
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
    # Grep for wkssvc.dll version < 6.0.6001.18270
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18270")){
      security_message(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for wkssvc.dll version < 6.0.6002.18049
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18049")){
       security_message(0);
    }
     exit(0);
  }
   security_message(0);
}

