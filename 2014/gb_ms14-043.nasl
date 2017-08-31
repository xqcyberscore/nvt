###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-043.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Microsoft Windows Media Center Remote Code Execution Vulnerability (2978742)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802079");
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-4060");
  script_bugtraq_id(69093);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-13 11:57:50 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Windows Media Center Remote Code Execution Vulnerability (2978742)");

  tag_summary =
"This host is missing an critical security update according to
Microsoft Bulletin MS14-043";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"MCPlayer fails to properly clean up resources after a CSyncBasePlayer
object is deleted.";

  tag_impact =
"Successful exploitation will allow remote attackers to arbitrary code in the
context of the current user.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

Windows Media Center for
 - Microsoft Windows 8 x32/x64 Edition
 - Microsoft Windows 8.1 x32/x64 Edition

Windows Media Center TV Pack for Windows Vista x32/x64 Edition
";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/library/security/ms14-043";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2978742");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-043");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
mcplayer_ver="";
media_center_ver="";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1,
                   winVista:3, winVistax64:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Confirm Windows Media Center TV Pack installed by checking version 5.1
## http://msdn.microsoft.com/en-us/library/ms815274.aspx
media_center_ver = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\Current" +
                                       "Version\Media Center", item:"Ident");

## Confirm Media Center is installed
if(!media_center_ver){
  exit(0);
}

## Get File version
mcplayer_ver = fetch_file_version(sysPath, file_name:"ehome\Mcplayer.dll");
if(!mcplayer_ver){
  exit(0);
}

## Windows 7
if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Mcplayer.dll version
  if(version_is_less(version:mcplayer_ver, test_version:"6.1.7601.18523") ||
     version_in_range(version:mcplayer_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22732")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and 8.1
else if(hotfix_check_sp(win8:1, win8x64:1, win8_1:1, win8_1x64:1) > 0)
{
  ## Only Professional edition is affected for Windows 8 and 8.1
  os_edition = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                               item:"EditionID");
  if("Professional">!< os_edition){
    exit(0);
  }

  ## Windows 8
  if(hotfix_check_sp(win8:1, win8x64:1) > 0)
  {
    ## Check for Mcplayer.dll version
    if(version_is_less(version:mcplayer_ver, test_version:"6.2.9200.17045") ||
       version_in_range(version:mcplayer_ver, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21161")){
      security_message(0);
    }
  }
  ## Windows 8.1
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    ## Check for Mcplayer.dll version
    if(version_is_less(version:mcplayer_ver, test_version:"6.3.9600.17224")){
      security_message(0);
    }
  }
  exit(0);
}

## Windows Vista
## Currently not supporting for Vista 64 bit
else if(hotfix_check_sp(winVista:3) > 0)
{
  ## Confirm Windows Media Center TV Pack for Windows Vista
  if("5.1" >!< media_center_ver){
    exit(0);
  }

  ## Check for Mcplayer.dll version
  if(version_is_less(version:mcplayer_ver, test_version:"6.1.1000.18324")){
    security_message(0);
  }
  exit(0);
}
