###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-085.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Windows Mail and Windows Meeting Space Remote Code Execution Vulnerability (2620704)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attacker to execute the arbitrary
  code or compromise a user's system.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is due to Windows Mail and Windows Meeting Space loading
  certain libraries in an insecure manner. This can be exploited to load
  arbitrary libraries by tricking a user into opening an EML or WCINV file
  located on a remote WebDAV or SMB share.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-085.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-085.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902486");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-2016");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-09 09:25:51 +0530 (Wed, 09 Nov 2011)");
  script_name("Windows Mail and Windows Meeting Space Remote Code Execution Vulnerability (2620704)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46752");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2620704");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-085");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-085 Hotfix (2620704)
if(hotfix_missing(name:"2620704") == 0){
  exit(0);
}

## Get Program Files Dir Path and construct complete path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                           item:"CommonFilesDir");
if(!sysPath){
  exit(0);
}

## Get Version from wab32.dll file
sysVer = fetch_file_version(sysPath, file_name:"\system\wab32.dll");
if(!sysVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for wab32.dll version
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18520")||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22721")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for wab32.dll version
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16890")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21061")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17698")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21829")){
    security_message(0);
  }
}
