###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_excel_ms13-073.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Office Excel Remote Code Execution Vulnerabilities (2858300)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902997");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159");
  script_bugtraq_id(62167, 62219, 62225);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-11 13:11:33 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerabilities (2858300)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-073.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws exists when processing XML data, which can be exploited to
disclose contents of certain local files by sending specially crafted XML
data including external entity references.";

  tag_impact =
"Successful exploitation will allow remote attackers to corrupt memory and
disclose sensitive information.

Impact Level: Application ";

  tag_affected =
"Microsoft Excel 2013
Microsoft Excel 2003 Service Pack 3 and prior
Microsoft Excel 2007 Service Pack 3 and prior
Microsoft Excel 2010 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-073";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2810048");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760583");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2760597");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2768017");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-073");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

# Variable Initialization
excelVer = "";

## Check for Office Excel 2003/2007/2010/2013
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^(11|12|14|15)\..*")
{
  ## Check version Excel.exe
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8403") ||
     version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6679.4999") ||
     version_in_range(version:excelVer, test_version:"14.0", test_version2:"14.0.7104.4999") ||
     version_in_range(version:excelVer, test_version:"15.0", test_version2:"15.0.4535.1002"))
  {
    security_message(0);
    exit(0);
  }
}
