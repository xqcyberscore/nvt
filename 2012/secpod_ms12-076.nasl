###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-076.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Office Remote Code Execution Vulnerabilities (2720184)
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.
  Impact Level: System/Application";
tag_affected = "Microsoft Excel Viewer
  Microsoft Excel 2003 Service Pack 3
  Microsoft Excel 2010 Service Pack 1 and prior
  Microsoft Office 2010 Service Pack 1 and prior
  Microsoft Excel 2007 Service Pack 2 and Service Pack 3
  Microsoft Office 2007 Service Pack 2 and Service Pack 3
  Microsoft Office Compatibility Pack Service Pack 2 and Service Pack 3";
tag_insight = "- An error when processing the 'SerAuxErrBar' record can be exploited to
    cause a heap-based buffer overflow via a specially crafted file.
  - An input validation error can be exploited to corrupt memory via a
    specially crafted file.
  - A use-after-free error when processing the 'SST' record can be
    exploited via a specially crafted file.
  - An error when processing certain data structures can be exploited to
    cause a stack-based buffer overflow via a specially crafted file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-076";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-076.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902930");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1885", "CVE-2012-1886", "CVE-2012-1887", "CVE-2012-2543");
  script_bugtraq_id(56425, 56426, 56430, 56431);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-11-14 08:46:19 +0530 (Wed, 14 Nov 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities (2720184)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51242/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687481");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687307");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687313");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2687311");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2597126");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-076");

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
excelVer = "";
excelviewVer = "";
xlcnvVer = "";

## Check for Office Excel 2003/2007/2010
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^(11|12|14)\..*")
{
  ## Check version Excel.exe
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8346") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6665.5002") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.6126.5002"))
  {
    security_message(0);
    exit(0);
  }
}

## Microsoft Office Excel Viewer 2007
excelviewVer = get_kb_item("SMB/Office/XLView/Version");
if(excelviewVer)
{
  ## check for Xlview.exe  version
  if(version_in_range(version:excelviewVer, test_version:"12.0", test_version2:"12.0.6665.5002"))
  {
    security_message(0);
    exit(0);
  }
}

## Check for Office Compatibility Pack 2007 and 2007
if(get_kb_item("SMB/Office/ComptPack/Version") =~ "^(12|14)\..*")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer)
  {
    ## Check for Office Excel Converter 2007/2010
    ## Checking Office Excel Converter 2010 is covered with Excel also.
    if(version_in_range(version:xlcnvVer, test_version:"12.0", test_version2:"12.0.6665.5002") ||
       version_in_range(version:xlcnvVer, test_version:"14.0", test_version2:"14.0.6126.5002")){
      security_message(0);
    }
  }
}
