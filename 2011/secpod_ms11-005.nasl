###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-005.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Windows Active Directory SPN Denial of Service (2478953)
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

tag_impact = "Successful exploitation will allows attackers to cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Windows Server 2003 Service Pack 2 and prior.";
tag_insight = "The flaw is due to an error in Active Directory that does not properly
  process specially crafted requests to update the service principal name (SPN).";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-005.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-005.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902290");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_cve_id("CVE-2011-0040");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft Windows Active Directory SPN Denial of Service (2478953)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2478953");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0319");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS11-005.mspx");

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

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3) <= 0){
  exit(0);
}

## Confirm Adcive Directory is insalled or not
if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS")){
  exit(0);
}

## MS11-005 Hotfix (2478953)
if(hotfix_missing(name:"2478953") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get the file Version
sysVer = fetch_file_version(sysPath, file_name:"system32\Ntdsa.dll");
if(!sysVer){
  exit(0);
}

## Windows Server 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
     ## Grep for Netlogon.dll version < 5.2.3790.4808
     if(version_is_less(version:sysVer, test_version:"5.2.3790.4808")){
       security_message(0);
     }
     exit(0);
  }
  security_message(0);
}
