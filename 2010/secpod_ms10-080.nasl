###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-080.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (2293211)
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
  tricking a user into opening a malicious Excel file.
  Impact Level: System/Application";
tag_affected = "Microsoft Excel Viewer Service Pack 2
  Microsoft Office Excel 2002 Service Pack 3
  Microsoft Office Excel 2003 Service Pack 3
  Microsoft Office Excel 2007 Service Pack 2
  Microsoft Office Compatibility Pack for Word,
  Excel, and PowerPoint 2007 File Formats Service Pack 2";
tag_insight = "The flaws are due to:
  - An integer overflow error when processing record information
  - A memory corruption error when processing malformed records
  - A memory corruption error when processing malformed Lotus 1-2-3 workbook
    (.wk3) file.
  - A memory corruption error when processing malformed formula information
  - A memory corruption error when processing malformed formula BIFF records
  - An out-of-bounds array when processing malformed records
  - An invalid pointer when processing malformed Merge Cell records.
  - A memory corruption error when processing negative future functions
  - An out-of-boundary access when processing malformed records
  - An array indexing error when processing malformed Real Time Data records
  - An out-of-bounds memory write when processing malformed data
  - A memory corruption error when processing malformed Ghost records";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-080.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-080.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902264");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3230", "CVE-2010-3231", "CVE-2010-3232", "CVE-2010-3233",
                "CVE-2010-3234", "CVE-2010-3235", "CVE-2010-3236", "CVE-2010-3237",
                "CVE-2010-3238", "CVE-2010-3239", "CVE-2010-3240", "CVE-2010-3241",
                "CVE-2010-3242");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2293211)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/Office/Excel/Version");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2345017");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2344893");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2345035");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2345088");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2344875");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2627");
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

# Check for Office Excel 2002/2003/2007
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^(10|11|12)\..*")
{
  # Check  Excel.exe 10.0 < 10.0.6866.0 or 11 < 11.0.8328.0 or 12.0 < 12.0.6545.5000
  if(version_in_range(version:excelVer, test_version:"10.0", test_version2:"10.0.6865") ||
     version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8327") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Office Compatiability Pack 2007
if(get_kb_item("SMB/Office/ComptPack/Version") =~ "^12\..*")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer)
  {
    # Check for Office Excel Converter 2007 version 12.0 < 12.0.6545.5000
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6545.4999"))
    {
      security_message(0);
      exit(0);
    }
  }
}

# Microsoft Office Excel Viewer 2007
excelVer = get_kb_item(name:"SMB/Office/XLView/Version");
if(!isnull(excelVer))
{
  # Xlview.exe 12 < 12.0.6545.5000
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6545.4999")){
    security_message(0);
  }
}
