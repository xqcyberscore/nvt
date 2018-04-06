###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_wordpad_mult_vuln.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# WordPad and Office Text Converter Memory Corruption Vulnerability (960477)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Update description and file check to reflect MS09-010 Bulletin.
#   - By Chandan S, 2009-04-15 21:34:24
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will let the attacker craft malicious arbitrary codes
  into the files and can trick the user to open those crafted documents which
  may lead to remote arbitrary code execution inside the context of the affected
  system.
  Impact Level: System";
tag_affected = "WordPad on MS Windows 2K/XP/2K3
  MS Office 2000 Word Service Pack 3
  MS Office XP Word Service Pack 3
  MS Office Converters Pack";
tag_insight = "- Input validation error when parsing document files i.e. Office files, RTF,
    Wordperfect files or Write files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-010.mspx";
tag_summary = "This host is missing a critical security update according to Microsoft
  Bulletin MS09-010.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900065");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4841", "CVE-2009-0087", "CVE-2009-0088", "CVE-2009-0235");
  script_bugtraq_id(29769);
  script_name("WordPad and Office Text Converter Memory Corruption Vulnerability (960477)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/default.aspx/kb/960477");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-010.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl",
                      "secpod_office_products_version_900032.nasl");
  script_require_keys("SMB/Office/Word/Version");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Shared Tools",
                          item:"SharedFilesDir");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:dllPath + "TextConv\MSCONV97.DLL");

dllVer = GetVer(file:file, share:share);

# Patch check for Office 2K and XP
if(get_kb_item("SMB/Office/Word/Version") =~ "^(9|10)\..*" &&
   get_kb_item("MS/Office/Ver") =~ "^(9|10)\..*")
{
  if(dllVer)
  {
    # Check for Hotfix 921606 (Office 2K) or 933399 (Office XP).
    if(hotfix_missing(name:"921606") == 1 || hotfix_missing(name:"933399") == 1)
    {
      if(version_is_less(version:dllVer, test_version:"2003.1100.8202.0"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Patch check for WordPad
if(registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                           "\App Paths\WORDPAD.EXE"))
{
  key = "SOFTWARE\Microsoft\Shared Tools\MSWord8\Clients";
  if(registry_key_exists(key:key)) 
  {

  foreach item (registry_enum_values(key:key))
  {
    if("wordpad" >< item)
    {
      # Check for Wordpad Hotfix 923561 (MS09-010)
      if(hotfix_missing(name:"923561") == 1)
      {
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:item);
        file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:item);

        wpVer = GetVer(file:file, share:share);
        if(wpVer != NULL)
        {
          if(hotfix_check_sp(win2k:5) > 0)
          {
            if(version_is_less(version:wpVer, test_version:"5.0.2195.7155")){
              security_message(0);
            }
          }
          else if(hotfix_check_sp(xp:4) > 0)
          {
            SP = get_kb_item("SMB/WinXP/ServicePack");
            if("Service Pack 2" >< SP)
            {
              if(version_is_less(version:wpVer, test_version:"5.1.2600.3355")){
                security_message(0);
              }
            }
            else if("Service Pack 3" >< SP)
            {
              if(version_is_less(version:wpVer, test_version:"5.1.2600.5584")){
                security_message(0);
              }
            }
          }
          else if(hotfix_check_sp(win2003:3) > 0)
          {
            SP = get_kb_item("SMB/Win2003/ServicePack");
            if("Service Pack 1" >< SP)
            {
              if(version_is_less(version:wpVer, test_version:"5.2.3790.3129")){
                security_message(0);
              }
            }
            else if("Service Pack 2" >< SP)
            {
              if(version_is_less(version:wpVer, test_version:"5.2.3790.4282")){
                security_message(0);
              }
            }
          }
        }
      }
    }
  }
  }
}

# Patch check for Office Converter Pack
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  convName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Microsoft Office Converter" >< convName)
  {
    if(!dllVer){
       exit(0);
    }

    # Check for Office Converter Hotfix 960476 (MS09-010)
    if(hotfix_missing(name:"960476") == 0){
      exit(0);
    }

    if(version_is_less(version:dllVer, test_version:"2003.1100.8202.0")){
      security_message(0);
    }
    exit(0);
  }
}
