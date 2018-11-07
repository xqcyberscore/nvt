###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4092460.nasl 12236 2018-11-07 05:34:17Z ckuersteiner $
#
# Microsoft Excel 2016 Information Disclosure Vulnerability (KB4092460)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.814110");
  script_version("$Revision: 12236 $");
  script_cve_id("CVE-2018-8429");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-07 06:34:17 +0100 (Wed, 07 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-12 11:22:15 +0530 (Wed, 12 Sep 2018)");
  script_name("Microsoft Excel 2016 Information Disclosure Vulnerability (KB4092460)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4092460");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Excel
  improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to disclose sensitive information.");

  script_tag(name:"affected", value:"Microsoft Excel 2016");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory. For updates
  refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4092460");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer){
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath){
  excelPath = "Unable to fetch the install path";
}

if(excelVer =~ "^(16\.)" && version_is_less(version:excelVer, test_version:"16.0.4744.1000"))
{
  report = report_fixed_ver(file_checked:excelPath + "Excel.exe",
                            file_version:excelVer, vulnerable_range:"16.0 - 16.0.4744.0999");
  security_message(data:report);
  exit(0);
}
