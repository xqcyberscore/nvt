###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-030.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerabilities (2663830)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.
  Impact Level: System/Application";
tag_affected = "Microsoft Excel Viewer
  Microsoft Excel 2003 Service Pack 3
  Microsoft Excel 2010 Service Pack 1 and prior
  Microsoft Office 2010 Service Pack 1 and prior
  Microsoft Excel 2007 Service Pack 2 and Service Pack 3
  Microsoft Office 2007 Service Pack 2 and Service Pack 3
  Microsoft Office Compatibility Pack Service Pack 2 and Service Pack 3";
tag_insight = "The flaws are due to errors while handling OBJECTLINK record,
  SXLI record, MergeCells record and an mismatch error when handling the Series
  record within Excel files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-030";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-030.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903026");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0141", "CVE-2012-0142", "CVE-2012-0143", "CVE-2012-0184",
                "CVE-2012-0185", "CVE-2012-1847");
  script_bugtraq_id(53342, 53373, 53374, 53375, 53379);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-09 10:19:21 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2663830)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597086");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597161");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597969");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596842");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597162");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597166");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553371");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-030");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version", "MS/Office/Ver", "SMB/Office/XLView/Version");

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

# Variable Initialization
path = "";
graphVer = "";
excelVer = "";
excelviewVer = "";
xlcnvVer = "";

# Check for Office Excel 2003/2007/2010
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^(11|12|14)\..*")
{
  # Check version Excel.exe
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8345") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6661.4999") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.6117.5002"))
  {
    security_message(0);
    exit(0);
  }

  ## Getting the office installed path(by using Excel, as it comes by default)
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\Excel.exe", item:"Path");
  if(path)
  {
    graphVer = fetch_file_version(sysPath:path, file_name:"graph.exe");
    if(graphVer)
    {
      if(version_in_range(version:graphVer, test_version:"12.0", test_version2:"12.0.6658.5003") ||
         version_in_range(version:graphVer, test_version:"14.0", test_version2:"14.0.6117.5002"))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}

# Microsoft Office Excel Viewer 2007
excelviewVer = get_kb_item(name:"SMB/Office/XLView/Version");
if(excelviewVer)
{
  # check for Xlview.exe  version
  if(version_in_range(version:excelviewVer, test_version:"12.0", test_version2:"12.0.6658.5003"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Office Compatibility Pack 2007
if(get_kb_item("SMB/Office/ComptPack/Version") =~ "^12\..*")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer)
  {
    # Check for Office Excel Converter 2007 version 12.0 < 12.0.6661.5000
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6661.4999")){
      security_message(0);
    }
  }
}
