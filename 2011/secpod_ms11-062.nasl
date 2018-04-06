###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-062.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# MS Windows Remote Access Service NDISTAPI Driver Privilege Elevation Vulnerability (2566454)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary
  code with kernel privileges via a specially crafted application.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.";
tag_insight = "The flaws are due to an input validation error in the Remote Access
  Service NDISTAPI driver (NDISTAPI.sys) when passing certain user-mode input
  to the kernel.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-062.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-062.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900298");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_bugtraq_id(48996);
  script_cve_id("CVE-2011-1974");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("MS Windows Remote Access Service NDISTAPI Driver Privilege Elevation Vulnerability (2566454)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45408");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2566454");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms11-062.mspx");

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
if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

## MS11-062 Hotfix (2566454)
if(hotfix_missing(name:"2566454") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Ndistapi.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\Ndistapi.sys");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Check for Ndistapi.sys version < 5.1.2600.6132
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6132")){
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
    ## Check for Ndistapi.sys version < 5.2.3790.4885
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4885")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
