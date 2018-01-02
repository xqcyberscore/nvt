###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-003.nasl 8228 2017-12-22 07:29:52Z teissa $
#
# Microsoft Office (MSO) Remote Code Execution Vulnerability (978214)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code.
  Impact Level: System";
tag_affected = "Microsoft Office XP 3 and prior";
tag_insight = "An unspecified issue exists in Mso.dll while handling specially crafted
  office files causing remote code execution.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-003.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-003.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900228");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0243");
  script_name("Microsoft Office (MSO) Remote Code Execution Vulnerability (978214)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/977896");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0336");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-003.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_reg_enum.nasl");
  script_mandatory_keys("MS/Office/Ver");
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

## Office XP
if(get_kb_item("MS/Office/Ver") =~ "^10\..*")
{
  ## Get Office File Path
  offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
  if(offPath)
  {
    offPath += "\Microsoft Shared\OFFICE10";
    dllVer = FileVer(file:"\Mso.dll", path:offPath);
    if(dllVer)
    {
      # Grep for Mso.dll version 10.0 < 10.0.6858.0
      if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6857.9"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
