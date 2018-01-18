###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-030.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Microsoft Outlook Express and Windows Mail Remote Code Execution Vulnerability (978542)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-17
#       - To detect file version 'Msoe.dll' on vista
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

tag_affected = "Microsoft Outlook Express 5.5 Service Pack 2
  Microsoft Outlook Express 6 Service Pack 1 on,
   - Microsoft Windows 2K Service Pack 4 and prior.

  Microsoft Outlook Express 6 on,
   - Microsoft Windows XP Service Pack 3 and prior.
   - Microsoft Windows 2K3 Service Pack 2 and prior.

  Windows Live Mail on,
   - Microsoft Windows XP Service Pack 3 and prior.
   - Microsoft Windows Vista Service Pack 1/2";

tag_impact = "Successful exploitation will let the remote attackers crash an affected
  client or can execute a arbitrary code by tricking a user into connecting
  to a malicious POP3 or IMAP server.
  Impact Level: System/Application";
tag_insight = "The issue is due to an integer overflow while processing responses
  received from a POP3 or IMAP server. This can be exploited by an attackers
  to crash an affected client or potentially execute arbitrary code by tricking
  a user into connecting to a malicious POP3 or IMAP server via a specially
  crafted STAT response.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-030.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-030.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900241");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_bugtraq_id(39927);
  script_cve_id("CVE-2010-0816");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Outlook Express and Windows Mail Remote Code Execution Vulnerability (978542)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39766");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1111");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3) <= 0){
  exit(0);
}

## Check registry for Outlook Express application
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Outlook Express")){
  exit(0);
}

## MS10-030 Hotfix check
if(hotfix_missing(name:"978542") == 0){
  exit(0);
}

## Get Program Files Path
dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"ProgramFilesDir");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\Outlook Express\Msoe.dll");

## Get Version
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

## Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  ## Grep for Msoe.dll version < 5.50.5010.200 and 6.0.2800.2001
  if(version_in_range(version:dllVer, test_version:"5.5", test_version2:"5.50.5010.199")||
     version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.2800.2000")){
     security_message(0);
  }
  exit(0);
}

## Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for Msoe.dll < 6.0.2900.3664
    if(version_is_less(version:dllVer, test_version:"6.0.2900.3664")){
      security_message(0);
    }
    exit(0);
  }

  else if("Service Pack 3" >< SP)
  {
    ## Grep for Msoe.dll < 6.0.2900.5931
    if(version_is_less(version:dllVer, test_version:"6.0.2900.5931")){
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
  if("Service Pack 2" >< SP)
  {
    # Grep for Msoe.dll version < 6.0.3790.4657
    if(version_is_less(version:dllVer, test_version:"6.0.3790.4657")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Get System32 path
dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
if(!dllPath){
  exit(0);
}
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\Windows Mail\Msoe.dll");

## Get Version
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Msoe.dll version < 6.0.6001.18416	
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18416")){
      security_message(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Msoe.dll version < 6.0.6002.18197
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18197")){
      security_message(0);
    }
     exit(0);
  }
  security_message(0);
}
