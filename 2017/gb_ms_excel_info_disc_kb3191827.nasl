###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_excel_info_disc_kb3191827.nasl 6012 2017-04-24 04:58:27Z teissa $
#
# Microsoft Office Excel Information Disclosure Vulnerability (KB3191827)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810685");
  script_version("$Revision: 6012 $");
  script_cve_id("CVE-2017-0194");
  script_bugtraq_id(97436);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-24 06:58:27 +0200 (Mon, 24 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-12 09:03:42 +0530 (Wed, 12 Apr 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Excel Information Disclosure Vulnerability (KB3191827)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office Excel according to Microsoft security update KB3191827.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists as Microsoft Office improperly
  discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and use the
  information to compromise the user's computer or data.

  Impact Level: Application");

  script_tag(name:"affected", value:"Microsoft Excel 2007 Service Pack 3");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link,
  https://support.microsoft.com/en-us/help/3191827");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/3191827");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

# Variable Initialization
excelVer = "";

## Check for Office Excel 2007 Version
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

## Check for Office Excel 2007 Path
excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath){
   excelPath = "Unable to fetch the install path";
}

##Check for Office Excel 2007
if((excelVer =~ "^12\.") && version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6766.4999"))
{
  report = 'File checked:     ' + excelPath + "Excel.exe" + '\n' +
           'File version:     ' + excelVer  + '\n' +
           'Vulnerable range: ' + "12.0 - 12.0.6766.4999" + '\n' ;
  security_message(data:report);
  exit(0);
}
