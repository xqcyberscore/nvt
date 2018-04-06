###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-033.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows Prtition Manager Privilege Elevation Vulnerability (2690533)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to gain escalated privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 Service Pack 1 and prior";
tag_insight = "The flaw is due to the way Windows Partition Manager (partmgr.sys)
  allocates objects in memory, when two or more processes or threads call
  Plug and Play (PnP) Configuration Manager functions at the same time.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-033";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-033.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902677");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0178");
  script_bugtraq_id(53378);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-09 10:08:42 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Windows Prtition Manager Privilege Elevation Vulnerability (2690533)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49115");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2690533");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-033");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

## Variables Initialization
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from partmgr.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\partmgr.sys");
if(!sysVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for partmgr.sys version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18600") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22820")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for partmgr.sys version
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16979") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21171")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17795")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21945")){
    security_message(0);
  }
}
