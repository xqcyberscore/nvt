###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-021.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (2489279)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  tricking a user into opening a malicious Excel file.
  Impact Level: System/Application";
tag_affected = "Microsoft Excel Viewer Service Pack 2
  Microsoft Office Excel 2002 Service Pack 3
  Microsoft Office Excel 2003 Service Pack 3
  Microsoft Office Excel 2007 Service Pack 2
  Microsoft Office Excel 2010";
tag_insight = "The flaws are caused by memory corruption, heap and integer overflows, buffer
  overwrite, array indexing, and dangling pointers when parsing malformed data or
  records within Excel documents, which could be exploited by attackers to execute
  arbitrary code by tricking a user into opening a specially crafted Excel file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-021.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-021.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902410");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0097", "CVE-2011-0098", "CVE-2011-0101", "CVE-2011-0103",
                "CVE-2011-0104", "CVE-2011-0105", "CVE-2011-0978", "CVE-2011-0979",
                "CVE-2011-0980");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2489279)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2466146");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2466169");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2502786");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2466158");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0940");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms11-021.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/Office/Excel/Version");
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

# Check for Office Excel 2002/2003/2007/2010
excelVer = get_kb_item("SMB/Office/Excel/Version");

if(excelVer =~ "^(10|11|12|14)\..*")
{
  # Check  version Excel.exe
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6868.0") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8331.0") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6550.5003") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.5130.5002"))
  {
    security_message(0);
    exit(0);
  }
}

# Microsoft Office Excel Viewer 2007
excelVer = get_kb_item(name:"SMB/Office/XLView/Version");
if(!isnull(excelVer))
{
  # check for Xlview.exe  version
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6550.5003")){
    security_message(0);
  }
}
