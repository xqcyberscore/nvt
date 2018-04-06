###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-048.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows SMB Server Remote Code Execution Vulnerability (2536275)
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code
  and cause a denial of service or compromise a vulnerable system.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior
  Microsoft Windows Server 2008 Service Pack 1/2 and prior";
tag_insight = "The flaw is caused when Microsoft Server Message Block (SMB) protocol
  software improperly handles SMB packets, including some pre-authentication
  scenarios.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-048.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-048.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902440");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-1267");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows SMB Server Remote Code Execution Vulnerability (2536275)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2536275");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS11-048.mspx");

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

## MS11-048 Hotfix (2536275)
if(hotfix_missing(name:"2536275") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from srvnet.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\srvnet.sys");
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

  if("Service Pack 1" >< SP)
  {
    ## Check for srvnet.sys version
    if(version_in_range(version:sysVer, test_version:"6.0.6001.18000", test_version2:"6.0.6001.18643")||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22909")){
      security_message(0);
    }
    exit(0);
  }
  if("Service Pack 2" >< SP)
  {
    ## Check for srvnet.sys version
    if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18461")||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22633")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for srvnet.sys version
  if(version_in_range(version:sysVer, test_version:"6.1.7600.16000", test_version2:"6.1.7600.16805")||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20955")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17607")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21716")){
    security_message(0);
  }
}
