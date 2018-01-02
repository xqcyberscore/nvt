###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-079.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (2293194)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted word document.
  Impact Level: System/Application";
tag_affected = "Microsoft Word 2010
  Microsoft Office Word Viewer
  Microsoft Office Word 2002 Service Pack 3
  Microsoft Office Word 2003 Service Pack 3
  Microsoft Office Word 2007 Service Pack 2
  Microsoft Office Compatibility Pack for Word,
  Excel, and PowerPoint 2007 File Formats Service Pack 2";
tag_insight = "The flaws are due to:
   - An uninitialized pointer error when processing malformed data in a Word file
   - An improper boundary check when processing certain data in a Word file
   - An error when handling index values within a Word document
   - A stack overflow error when processing malformed data within a Word
     document
   - An error when handling return values, bookmarks, pointers while parsing
     a specially crafted Word
   - A heap overflow error when handling malformed records within a Word file
   - An error when handling indexes while parsing a specially crafted Word file";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-079.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-079.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902265");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-2747", "CVE-2010-2748", "CVE-2010-2750", "CVE-2010-3214",
                "CVE-2010-3215", "CVE-2010-3216", "CVE-2010-3217", "CVE-2010-3218",
                "CVE-2010-3219", "CVE-2010-3220", " CVE-2010-3221");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2293194)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2328360");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2344993");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2344911");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2345043");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2345000");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2626");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");
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


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

## Microsoft Office Word 2002/2003/2007
winwordVer = get_kb_item("SMB/Office/Word/Version");
if(!isnull(winwordVer))
{
  # Grep for version Winword.exe 10 < 10.0.6866.0 , 12 < 12.0.6545.5000, 11< 11.0.8328.0	
  if(version_in_range(version:winwordVer, test_version:"10.0", test_version2:"10.0.6865.0") ||
     version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8327.0") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6545.4999") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.5120.4999"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Office Word Version 2007 with compatiability pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(!isnull(wordcnvVer))
{
  # Check for Word Converter 2007 version 12.0 < 12.0.6545.5000	
  if(version_in_range(version:wordcnvVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
  {
    security_message(0);
    exit(0);
  }
}
