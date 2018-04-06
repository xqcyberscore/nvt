###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-096.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft Office Excel Remote Code Execution Vulnerability (2640241)
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

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.
  Impact Level: System/Application";
tag_affected = "Microsoft Excel 2003 Service Pack 3";
tag_insight = "The flaw is due to an error when handling certain objects while
  parsing records and can be exploited to corrupt memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-096";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-096.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902494");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-3403");
  script_bugtraq_id(50954);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-14 16:18:42 +0200 (Wed, 14 Dec 2011)");
  script_name("Microsoft Office Excel Remote Code Execution Vulnerability (2640241)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Excel/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47203");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2596954");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-096");
  exit(0);
}

include("version_func.inc");

# Check for Office Excel 2003
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

if(excelVer =~ "^11\..*")
{
  # Check version Excel.exe
  if(version_in_range(version:excelVer, test_version:"11.0", test_version2:"11.0.8341.0")){
    security_message(0);
  }
}
