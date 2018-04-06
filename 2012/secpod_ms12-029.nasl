###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-029.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Word Remote Code Execution Vulnerability (2680352)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_affected = "Microsoft Office Word 2003 Service Pack 3
  Microsoft Office Word 2007 Service Pack 2
  Microsoft Office Word 2007 Service Pack 3
  Microsoft Office Compatibility Pack for File Formats Service Pack 2";
tag_insight = "The flaw is due to an error when parsing Rich Text Format (RTF) data
  and can be exploited to corrupt memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS12-029";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-029.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902911");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0183");
  script_bugtraq_id(53344);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-09 09:26:38 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerability (2680352)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596880");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2598332");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596917");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS12-029");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

winwordVer = "";
wordcnvVer = "";

# Microsoft Office Word 2003/2007
winwordVer = get_kb_item("SMB/Office/Word/Version");
if(winwordVer)
{
  # Grep for version Winword.exe 12 < 12.0.6661.5000, 11< 11.0.8345
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8344") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6661.4999"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Office Word Version 2007 with compatiability pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer)
{
  # Check for Word Converter 2007 version 12.0 < 12.0.6661.5000
  if(version_in_range(version:wordcnvVer, test_version:"12.0", test_version2:"12.0.6661.4999"))
  {
    security_message(0);
    exit(0);
  }
}
