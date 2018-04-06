###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-027.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (969514)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could execute arbitrary code on the remote system
  via a specially crafted Word document.
  Impact Level: System/Application";
tag_affected = "Microsoft Word Viewer 2003
  Microsoft Office 2K/XP/2003/2007";
tag_insight = "The flaws are due to boundary errors when parsing certain records that can be
  exploited to cause a buffer overflow.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-027.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-027.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900365");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-10 19:23:54 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0563", "CVE-2009-0565");
  script_bugtraq_id(35188, 35190);
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (969514)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35377");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/969514");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-027.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "MS/Office/Prdts/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

# Check for Office Word 2000, XP, 2003 and 2007
if(egrep(pattern:"^(9|10|11|12)\..*", string:get_kb_item("MS/Office/Ver")))
{
  # Grep for Office Word Version from KB
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  # Check for Office Word 9.0 < 9.0.0.8979
  if(version_in_range(version:wordVer, test_version:"9.0",
                      test_version2:"9.0.0.8978")){
    security_message(0);
  }
  # Check for Office Word 10.0 < 10.0.6854.0
  else if(version_in_range(version:wordVer, test_version:"10.0",
                           test_version2:"10.0.6853.0")){
    security_message(0);
  }
  # Check for Office Word 11.0 < 11.0.8307.0
  else if(version_in_range(version:wordVer, test_version:"11.0",
                           test_version2:"11.0.8306.0")){
    security_message(0);
  }
  # Check for Office Word 12.0 < 12.0.6504.5000
  else if(version_in_range(version:wordVer, test_version:"12.0",
                           test_version2:"12.0.6504.4999")){
    security_message(0);
  }
}

# Check for Office Word Version 2007 with compatiability pack
if(get_kb_item("SMB/Office/Word/Version") =~ "^(12)\..*" )
{
  wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
  if(!wordcnvVer){
    exit(0);
  }

  # Check for Word Converter 2007 version 12.0 < 12.0.6500.5000
  if(version_in_range(version:wordcnvVer, test_version:"12.0",
                      test_version2:"12.0.6500.4999")){
    security_message(0);
  }
}

# Check for Word Viewer 11.0 < 11.0.8307.0
wordviewVer = get_kb_item("SMB/Office/WordView/Version");
if(wordviewVer != NULL)
{
  if(version_in_range(version:wordviewVer, test_version:"11.0",
                      test_version2:"11.0.8306.0")){
    security_message(0);
  }
}
