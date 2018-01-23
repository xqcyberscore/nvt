###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-087.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Microsoft Office Remote Code Execution Vulnerabilities (2423930)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code.
  Impact Level: System";
tag_affected = "Microsoft Office XP Service Pack 3
  Microsoft Office 2003 Service Pack 3
  Microsoft Office 2007 Service Pack 2
  Microsoft Office 2010.";
tag_insight = "Multiple flaws are caused by,
  - a stack overflow error when processing malformed Rich Text Format data.
  - a memory corruption error when processing Office Art Drawing records in
    Office files.
  - a memory corruption error when handling drawing exceptions.
  - a memory corruption error when handling SPID data in Office documents.
  - an error when loading certain librairies from the current working directory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-087.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-087.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901166");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-10 14:58:25 +0100 (Wed, 10 Nov 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3333", "CVE-2010-3334", "CVE-2010-3335",
                "CVE-2010-3336", "CVE-2010-3337");
  script_bugtraq_id(44652, 44656, 44659, 44660, 42628);
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2423930)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38521");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2923");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-087.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Get File Version
function FileVer (file, path)
{
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  if(share =~ "[a-z]\$")
    share = toupper(share);
  file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path + file);
  ver = GetVer(file:file, share:share);
  return ver;
}

## MS Office XP, 2003, 2007, 2010
if(get_kb_item("MS/Office/Ver") =~ "^[10|11|12|14].*")
{
  ## Get Office File Path
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
  if(! path) {
    exit(0);
  }

  foreach ver (make_list("OFFICE10", "OFFICE11", "OFFICE12", "OFFICE14"))
  {
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = FileVer(file:"\Mso.dll", path:offPath);
    if(dllVer)
    {
      ## Grep for Mso.dll versions
      if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6866.9")   ||
         version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8328.9")   ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6545.5003")||
         version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.5128.4999"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
