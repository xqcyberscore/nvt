##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-043_900028.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description:  Microsoft Excel Could Allow Remote Code Execution Vulnerabilities (954066)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Remote attackers could be able to corrupt memory locations via a
 specially crafted Excel (.xls) files.
 Impact Level : System";

tag_solution = "Run Windows Update and update the listed hotfixes or download and
 update mentioned hotfixes in the advisory from the below link.
 http://www.microsoft.com/technet/security/bulletin/ms08-043.mspx";

tag_affected = "Microsoft Excel 2002/XP/2003/2007 on Windows (All).
 Microsoft Excel Viewer 2003/2007 on Windows (All).";

tag_insight = "Multiple flaw are due to,
 - index values are not properly validated when loading Excel files into memory.
 - an errors during processing/parsing of certain array indexes and record
   values when loading Excel files into memory.
 - a password strings to remote data sources are not being properly deleted even
   when configured to not store credentials.";


tag_summary = "This host is missing critical security update according to
 Microsoft Bulletin MS08-043.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900028");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
 script_bugtraq_id(30638, 30639, 30640, 30641);
 script_cve_id("CVE-2008-3003", "CVE-2008-3004", "CVE-2008-3005", "CVE-2008-3006");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
 script_family("Windows : Microsoft Bulletins");
 script_name("Microsoft Excel Could Allow Remote Code Execution Vulnerabilities (954066)");
 script_dependencies("secpod_reg_enum.nasl", "secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
 script_mandatory_keys("MS/Office/Ver", "SMB/Office/Excel/Version");

 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-043.mspx");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name:"qod_type", value:"registry");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

include("version_func.inc");

if(egrep(pattern:"^(9|10|11|12)\..*", string:get_kb_item("MS/Office/Ver")))
{
  excelVer = get_kb_item("SMB/Office/Excel/Version");
  if(!excelVer){
    exit(0);
  }

  if(version_in_range(version:excelVer, test_version:"9.0",
                      test_version2:"9.0.0.8970")){
    security_message(0);
  }
  else if(version_in_range(version:excelVer, test_version:"10.0",
                           test_version2:"10.0.6844")){
    security_message(0);
  }
  else if(version_in_range(version:excelVer, test_version:"11.0",
                           test_version2:"11.0.8219")){
    security_message(0);
  }
  else if(version_in_range(version:excelVer, test_version:"12.0",
                           test_version2:"12.0.6323.4999")){
    security_message(0);
  }
}
