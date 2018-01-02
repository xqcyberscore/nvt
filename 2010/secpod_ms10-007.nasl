###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-007.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# Microsoft Windows Shell Handler Could Allow Remote Code Execution Vulnerability (975713)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execure a binary
  from the local client system.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K  Service Pack 4 and prior.
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.";
tag_insight = "An error exists due to incorrect validation of input sent to the ShellExecute
  API function. Remote attacker could exploit this vulnerability to execute a
  binary from the local client system by making a victim to click on a
  specially-crafted URL.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-007.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-007.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900227");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0027");
  script_bugtraq_id(37884);
  script_name("Microsoft Windows Shell Handler Could Allow Remote Code Execution Vulnerability (975713)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55773");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/975713");

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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# MS10-007 Hotfix check
if(hotfix_missing(name:"975713") == 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\Shlwapi.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Shlwapi.dll version < 5.0.3900.7349
  if(version_is_less(version:dllVer, test_version:"5.0.3900.7349")){
    security_message(0);
  }
}

# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Shlwapi.dll < 6.0.2900.3653
    if(version_is_less(version:dllVer, test_version:"6.0.2900.3653")){
      security_message(0);
    }
    exit(0);
  }

  else if("Service Pack 3" >< SP)
  {
    # Grep for Shlwapi.dll < 6.0.2900.5912
    if(version_is_less(version:dllVer, test_version:"6.0.2900.5912")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Shlwapi.dll version < 6.0.3790.4603
    if(version_is_less(version:dllVer, test_version:"6.0.3790.4603")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
