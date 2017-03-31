###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-055.nasl 5361 2017-02-20 11:57:13Z cfi $
#
# Remote Code Execution Vulnerability in Cinepak Codec (982665)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#  
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-11
#  - To detect file version 'Iccvid.dll' on vista, win 7 os
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code with the privileges of the user running the application.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows Vista service Pack 2 and prior.
  Microsoft Windows 7";
tag_insight = "The Cinepak Codec applications fails to perform adequate boundary checks
  while handling supported format files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-055.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-055.";

if(description)
{
  script_id(900249);
  script_version("$Revision: 5361 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 12:57:13 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_bugtraq_id(42256);
  script_cve_id("CVE-2010-2553");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Remote Code Execution Vulnerability in Cinepak Codec (982665)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40936");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/982665");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-055.mspx");

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

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, winVista:3, win7:1) <= 0){
  exit(0);
}
## MS10-050 Hotfix check
if(hotfix_missing(name:"982665") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"Iccvid.dll");
  if(!dllVer){
    exit(0);
  }

  ## Windows xp
  if(hotfix_check_sp(xp:4) > 0)
  {
    ## Grep for Iccvid.dll version < 1.10.0.13
    if(version_is_less(version:dllVer, test_version:"1.10.0.13")){
       security_message(0);
    }
        exit(0);
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

dllVer = get_file_version(sysPath, file_name:"System32\iccvid.dll");
if(!dllVer){
  exit(0);
}

## Windows Vista and Windows 7
if(hotfix_check_sp(winVista:3, win7:1) > 0)
{
  ## Grep for Iccvid.dll version < 1.10.0.13
  if(version_is_less(version:dllVer, test_version:"1.10.0.13")){
      security_message(0);
  }
}

