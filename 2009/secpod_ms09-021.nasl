###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-021.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (969462)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
# Sharath S <ssharath@secpod.com>
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
  and corrupt memory, buffer overflow via a specially crafted Excel file.
  Impact Level: System/Application";
tag_affected = "Microsoft Excel Viewer 2003/2007
  Microsoft Office Excel 2000/2002/2003/2007";
tag_insight = "The flaws are due to
  - an array-indexing error when processing certain records by using corrupted
    object.
  - a boundary error when parsing certain records by opening a specially
    crafted Excel file.
  - an integer overflow error when processing the number of strings in a file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-021.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-021.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900670");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-12 17:18:17 +0200 (Fri, 12 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0549", "CVE-2009-0557", "CVE-2009-0558", "CVE-2009-0559",
                "CVE-2009-0560", "CVE-2009-0561", "CVE-2009-1134");
  script_bugtraq_id(35215, 35241, 35242, 35243, 35244, 35245, 35246);
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (969462)");


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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35364");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/969462");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-021.mspx");
  exit(0);
}

include("version_func.inc");

# Check for Office Excel 2000/2002/2003/2007
if(egrep(pattern:"^(9|10|11|12)\..*", string:get_kb_item("MS/Office/Ver")))
{
  excelVer = get_kb_item("SMB/Office/Excel/Version");
  if(excelVer != NULL)
  {
    # Check for Office Excell-2000 9.0 < 9.0.0.8979
    if(version_in_range(version:excelVer, test_version:"9.0",
                      test_version2:"9.0.0.8978")){
      security_message(0);
    }
    # Check for Office Excel-2002 10.0 < 10.0.6854.0
    else if(version_in_range(version:excelVer, test_version:"10.0",
                           test_version2:"10.0.6853.0")){
      security_message(0);
    }
    # Check for Office Excel-2003 11.0 < 11.0.8307.0
    else if(version_in_range(version:excelVer, test_version:"11.0",
                           test_version2:"11.0.8306.0")){
      security_message(0);
    }
    # Check for Office Excel-2007 12.0 < 12.0.6504.5001
    else if(version_in_range(version:excelVer, test_version:"12.0",
                           test_version2:"12.0.6504.5000")){
     security_message(0);
    }
  }
}

# Check for Office Excel Version 2003/2007 with compatiability pack
if(get_kb_item("SMB/Office/Excel/Version") =~ "^(11|12)\..*" )
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer != NULL)
  {
    # Check for Office Excel Converter 2007 version 12.0 < 12.0.6504.5001
    if(version_in_range(version:xlcnvVer, test_version:"12.0",
                      test_version2:"12.0.6504.5000"))
    { 
      security_message(0);
      exit(0);
    }
  }
}

# For Microsoft Office Excel Viewer 2003/2007
xlviewVer = get_kb_item("SMB/Office/XLView/Version");
if(xlviewVer != NULL)
{
 # Check for Office Excel Viewer 2003 version 11.0 < 11.0.8307.0 or
 # Office Excel Viewer 2007 version 12.0 < 12.0.6504.5000
 if(version_in_range(version:xlviewVer, test_version:"11.0",
                     test_version2:"11.0.8306.0") ||
    version_in_range(version:xlviewVer, test_version:"12.0",
                    test_version2:"12.0.6504.4999")){
    security_message(0);
  }
}
