###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-068.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# MS Local Security Authority Subsystem Service Privilege Elevation Vulnerability (983539)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow the remote attacker who has previously
  authenticated with the LSASS server to execute arbitrary code with SYSTEM
  privileges.
  Impact Level: System/Application.";
tag_affected = "Microsoft Windows 7
  Microsoft Windows Vista Service Pack 2
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows Server 2003 Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is caused by a heap overflow error in the Local Security Authority
  Subsystem Service (LSASS) when handling Lightweight Directory Access Protocol
  (LDAP) messages in certain implementations of Active Directory, Active
  Directory Application Mode (ADAM), and Active Directory Lightweight Directory
  Service (AD LDS).";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-068.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-068.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902244");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0820");
  script_name("MS Local Security Authority Subsystem Service Privilege Elevation Vulnerability (983539)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/981550");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/982000");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2389");

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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

# Active Directory
if((hotfix_missing(name:"981550") == 1) &&
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
      # Windows 2K3
      if(hotfix_check_sp(win2003:3) > 0)
      {
        SP = get_kb_item("SMB/Win2003/ServicePack");
        if("Service Pack 2" >< SP)
        {
          # Check for Ntdsa.dll version < 5.2.3790.4754
          if(version_is_less(version:ntdsaVer, test_version:"5.2.3790.4754")){
            security_message(0);
          }
          exit(0);
        }
        security_message(0);
      }
    }
  }
}

# Active Directory Application Mode
if((hotfix_missing(name:"982000)") == 1) &&
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
        if(XPSP =~ "Service Pack (2|3)" || ("Service Pack 2" >< k3SP))
        {
          # Check for Adamdsa.dll version < 1.1.3790.4722
          if(version_is_less(version:adamdsaVer, test_version:"1.1.3790.4722")){
            security_message(0);
          }
          exit(0);
        }
        security_message(0);
      }
    }
  }
}

if((hotfix_missing(name:"981550") == 0)){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                        item:"PathName");
if(!sysPath){
 exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                   string:sysPath + "\system32\Ntdsai.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Rtutils.dll version < 6.0.6001.18461
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18461")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rtutils.dll version < 6.0.6002.18244
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18244")){
      security_message(0);
    }
    exit(0);
  }
   security_message(0);
}

# Windows Server 2008
 else if(hotfix_check_sp(win2008:2) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Ntdsai.dll version < 1.626.6001.18461
    if(version_is_less(version:sysVer, test_version:"1.626.6001.18461")){
     security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Ntdsai.dll version < 6.0.6002.18244
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18244")){
      security_message(0);
    }
     exit(0);
  }
    security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  ## Grep for Ntdsai.dll version < 6.1.7600.16612
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16612")){
    security_message(0);
  }
}
