###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-074.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Office Project Remote Code Execution Vulnerability (967183)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
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

tag_impact = "Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into opening a
  specially crafted document.
  Impact Level: System/Apllication";
tag_affected = "Microsoft Project 2002 Service Pack 1
  Microsoft Project 2000 Service Release 1
  Microsoft Office Project 2003 Service Pack 3";
tag_insight = "This issue is due to application not properly validating resource allocations
  when opening Project files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-074.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-074.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901069");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0102");
  script_name("Microsoft Office Project Remote Code Execution Vulnerability (967183)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/961083");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/961079");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/961082");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3439");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS09-074.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

# MS09-074 Hotfix check
if((hotfix_missing(name:"961082") == 0) || (hotfix_missing(name:"961083") == 0)
   || (hotfix_missing(name:"961079") == 0)){
   exit(0);
}


function find_version(filepath)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:filepath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:filepath);
  dllVer = GetVer(file:file, share:share);
  return dllVer;
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows" +
                         "\CurrentVersion", item:"ProgramFilesDir");
if(!dllPath){
  exit(0);
}

foreach path (make_list("\MS Project",
                        "\Microsoft Office Project",
                        "\Microsoft Office Project 10",
                        "\Microsoft Office Project 9",
                        "\Microsoft Office Project 11"))
{
  Ver = find_version(filepath:dllPath + "\Common Files\Microsoft Shared"
                              + path + "\ATLCONV.DLL");
  if(Ver)
  {
    # Grep for ATLCONV.DLL version <  9.0.2001.1109, 10.0.2108.2216,11.3.2008.1717
    if(version_in_range(version:Ver, test_version:"9.0", test_version2:"9.0.2001.1108") ||
       version_in_range(version:Ver, test_version:"10.0", test_version2:"10.0.2108.2215") ||
       version_in_range(version:Ver, test_version:"11.0", test_version2:"11.3.2008.1716")){
       security_message(0);
       exit(0);
    }
  }
}
