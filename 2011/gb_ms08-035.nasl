###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-035.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Active Directory Denial of Service Vulnerability (953235)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attacker to send specially crafted LDAP
  packets to cause the target system to stop responding and automatically restart.
  Impact Level: System/Application.";
tag_affected = "Microsoft Windows 2K  Service Pack 4 and prior
  Microsoft Windows XP  Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows 2008 server Service Pack 2 and prior";
tag_insight = "The issue is due to an input validation error in the processing of
  LDAP requests. This can be exploited to cause a vulnerable system to stop
  responding and automatically restart via a specially crafted LDAP packet sent
  to the Active Directory Application Mode (ADAM), Active Directory, or AD LDS server.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-035.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-035.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801721");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-18 10:00:48 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-1445");
  script_bugtraq_id(29584);
  script_name("Microsoft Active Directory Denial of Service Vulnerability (953235)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30586");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Jun/1020229.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-035.mspx");
  
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:3) <= 0){
  exit(0);
}

# Active Directory
if((hotfix_missing(name:"949014") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS\Performance"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(dllPath != NULL)
  {
    # Get the version of Active Directory
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    ntdsaFile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                             string:dllPath + "\Ntdsa.dll");
    ntdsaVer = GetVer(file:ntdsaFile, share:share);
    if(ntdsaVer != NULL)
    {
      # Windows 2K
      if(hotfix_check_sp(win2k:5) > 0)
      {
        # Check for Ntdsa.dll version < 5.0.2195.7155
        if(version_is_less(version:ntdsaVer, test_version:"5.0.2195.7155"))
        {
          security_message(0);
          exit(0);
        }
      }
      # Windows 2K3
      else if(hotfix_check_sp(win2003:3) > 0)
      {
        SP = get_kb_item("SMB/Win2003/ServicePack");
        if("Service Pack 1" >< SP)
        {
          # Check for Ntdsa.dll version < 5.2.3790.3122
          if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.3122")){
            security_message(0);
          }
          exit(0);
        }
        
        if("Service Pack 2" >< SP)
        {
          # Check for Ntdsa.dll version < 5.2.3790.4274
          if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.4274")){
            security_message(0);
          }
          exit(0);
        }
        security_message(0);
      }
    }
  }

  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
  if(sysPath)
  {
    dllVer = fetch_file_version(sysPath, file_name:"System32\Ntdsai.dll");
    if(dllVer)
    {
      ## Windows Server 2008
      if(hotfix_check_sp(win2008:3) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");
        if("Service Pack 1" >< SP)
        {
          ## Check for Ntdsai.dll version < 6.0.6001.18072
          if(version_is_less(version:dllVer, test_version:"6.0.6001.18072")){
             security_message(0);
          }
          exit(0);
        }
      }
    }
  }
}

# Active Directory Application Mode
if((hotfix_missing(name:"949269") == 1) &&
   registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\ADAM\Linkage"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(dllPath != NULL)
  {
    # Get the version of Active Directory Application Mode
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    adamdsaFile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                              string:dllPath - "system32" + "ADAM\Adamdsa.dll");
    adamdsaVer = GetVer(file:adamdsaFile, share:share);
    if(adamdsaVer != NULL)
    {
      # Windows XP/2K3
      if(hotfix_check_sp(xp:4, win2003:3) > 0)
      {
        XPSP = get_kb_item("SMB/WinXP/ServicePack");
        k3SP = get_kb_item("SMB/Win2003/ServicePack");
        if(XPSP =~ "Service Pack (2|3)")
        {
          # Check for Adamdsa.dll version < 1.1.3790.4276
          if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4276")){
            security_message(0);
          }
          exit(0);
        }
        
        if("Service Pack 1" >< k3SP)
        {
          # Check for Adamdsa.dll version < 1.1.3790.3129
          if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.3129")){
            security_message(0);
          }
          exit(0);
        }
        
        if("Service Pack 2" >< k3SP)
        {
          # Check for Adamdsa.dll version < 1.1.3790.4281
          if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4281")){
            security_message(0);
          }
          exit(0);
        } 
      } 
    }
  }
}
