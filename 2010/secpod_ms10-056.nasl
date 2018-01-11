###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-056.nasl 10593 2010-08-11 12:12:09Z aug$
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (2269638)
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
  tricking a user into opening a specially crafted Excel document.
  Impact Level: System/Application";
tag_affected = "Microsoft Office Word Viewer
  Microsoft Office Word 2002 Service Pack 3
  Microsoft Office Word 2003 Service Pack 3
  Microsoft Office Word 2007 Service Pack 2
  Microsoft Office Compatibility Pack for Word,
  Excel, and PowerPoint 2007 File Formats Service Pack 2";
tag_insight = "The issues are caused by buffer overflow and memory corruption errors when
  processing malformed data and records within Word and 'RTF' documents, which
  could be exploited by attackers to crash an affected application or execute
  arbitrary code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-056.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-056.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902228");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_cve_id("CVE-2010-1900","CVE-2010-1901", "CVE-2010-1902", "CVE-2010-1903");
  script_bugtraq_id(42133, 42132);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2269638)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2251389");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2251399");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2251437");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2251419");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2053");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-056.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

## Microsoft Office Word 2002/2003/2007
winwordVer= get_kb_item("SMB/Office/Word/Version");
if(!isnull(winwordVer))
{
  # Grep for version Winword.exe 10 < 10.0.6864.0 , 12 < 12.0.6541.5000	, 11< 11.0.8326.0	
  if(version_in_range(version:winwordVer, test_version:"10.0", test_version2:"10.0.6863.0") ||
     version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8325.0") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6541.4999"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Office Word Version 2007 with compatiability pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(!isnull(wordcnvVer))
{
  # Check for Word Converter 2007 version 12.0 < 12.0.6539.5000	
  if(version_in_range(version:wordcnvVer, test_version:"12.0", test_version2:"12.0.6539.4999"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Word Viewer 11.0 < 11.0.8326.0
wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer != NULL)
{
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8325.0")){
    security_message(0);
  }
}
