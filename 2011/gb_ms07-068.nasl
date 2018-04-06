###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms07-068.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Vulnerability in Windows Media File Format Could Allow Remote Code Execution
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright: 
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code with
  SYSTEM-level privileges. Successfully exploiting this issue will result in
  complete compromise of the affected computers.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K/XP/2003/Vista";
tag_insight = "The flaws are due to boundary errors when parsing ASF
  (Advanced Systems Format) files which can be exploited to cause heap-based
  buffer overflows when a user views a specially crafted ASF file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms07-068.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS07-068.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801708");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-14 07:39:17 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0064");
  script_bugtraq_id(26776);
  script_name("Vulnerability in Windows Media File Format Could Allow Remote Code Execution");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28034");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2007/Dec/1019074.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms07-068.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

# Windows Media Format Runtime 7.1, 9.0, 9.5 and 11 on 2K/XP/2003
dllVer = fetch_file_version(sysPath, file_name:"wmasf.dll");
if(dllVer)
{
  # Check for Hotfix 941569
  if(hotfix_missing(name:"941569") == 1)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for version 
      if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.10.0.3080") ||
         version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.0.3266")){
        security_message(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"9.0", test_version2:"9.0.0.3266") ||
           version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.0.4059") ||
           version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.5721.5237")){
                      security_message(0);
        }
      }
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.0.3709")){
           security_message(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.0.3999")){
          security_message(0);
        }
      }
      security_message(0);
    }
  }
}
    
## Get system path for windows vista
dllPath = smb_get_system32root();
if(!dllPath){
   exit(0);
}

dllVer = fetch_file_version(sysPath:dllPath, file_name:"wmasf.dll");
if(dllVer)
{
  # Check for Hotfix 941569
  if(hotfix_missing(name:"941569") == 1)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for wmasf.dll version < 11.0.6000.6345
        if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6000.6344")){
          security_message(0);
        }
         exit(0);
      }
    }
  }
}

# Windows Media Services 9.1 on Windows 2003
# Check for Hotfix 944275
if(hotfix_missing(name:"944275") == 1)
{
  if(hotfix_check_sp(win2003:3) > 0)
  {
    dllVer = fetch_file_version(sysPath, file_name:"windows media\server\Wmsserver.dll");

    if(dllVer != NULL)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.1.1.3843")){
          security_message(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.1.1.3861")){
          security_message(0);
        }
      }
      else security_message(0);
    }
  }
}
