###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-031.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Microsoft Visual Basic Remote Code Execution Vulnerability (978213)
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

tag_impact = "Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a
  specially crafted document.
  Impact Level: System/Apllication";
tag_affected = "Microsoft Office XP SP3 and prior.
  Microsoft Office 2003 SP3 and prior.
  Microsoft Visual Basic for Applications.
  2007 Microsoft Office System SP2 and prior.
  Microsoft Visual Basic for Applications SDK.";
tag_insight = "The issue is caused by a stack memory corruption error in 'VBE6.DLL' when
  searching for ActiveX controls in a document that supports VBA.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-031.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-031.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902178");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-0815");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Visual Basic Remote Code Execution Vulnerability (978213)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976380");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976382");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976321");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/974945");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1121");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-031.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_reg_enum.nasl");
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

if(hotfix_check_sp(xp:4, win2003:3, win2k:5) <= 0){
  exit(0);
}

## Confirm installation of Visual Basic for Applications IDE
key = registry_key_exists(key:"SOFTWARE\Microsoft\Shared Tools\AddIn Designer" +
                              "\Visual Basic for Applications IDE");

### Confirm the office XP, 2003, 2007 installation.
officeVer = get_kb_item("MS/Office/Ver");

if(isnull(key))
{
  if(isnull(officeVer)){
    exit(0);
  }
}

if((officeVer =~ "^(10|11|12)\..*") || !isnull(key))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows" +
                         "\CurrentVersion", item:"ProgramFilesDir");
  if(!dllPath){
    exit(0);
  }

  ## Check for VBE6.DLL file installed location.
  dllPath = dllPath + "\Common Files\Microsoft Shared\VBA\VBA6\VBE6.DLL";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    exit(0);
  }

  ## Check for VBE6.DLL version less than 6.5.10.53
  if(version_is_less(version:dllVer, test_version:"6.5.10.53")){
    security_message(0);
  }
}
