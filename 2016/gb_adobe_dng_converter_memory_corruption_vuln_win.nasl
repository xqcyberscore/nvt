###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_dng_converter_memory_corruption_vuln_win.nasl 4899 2017-01-02 07:35:17Z antu123 $
#
# Adobe DNG Converter Memory Corruption Vulnerability - (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:dng_converter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809763");
  script_version("$Revision: 4899 $");
  script_cve_id("CVE-2016-7856");
  script_bugtraq_id(94875);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 08:35:17 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-12-15 17:16:00 +0530 (Thu, 15 Dec 2016)");
  script_name("Adobe DNG Converter Memory Corruption Vulnerability - (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe DNG
  Converter and is prone to memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  run arbitrary code execution or conduct a denial-of-service condition.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Adobe DNG Converter prior to version 9.8 on
  Windows");

  script_tag(name:"solution", value:"Upgrade to Adobe DNG Converter version 9.8
  or later. For updates refer to,
  https://www.adobe.com/support/downloads/product.jsp?product=106&platform=Windows");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dng-converter/apsb16-41.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_dng_converter_detect_win.nasl");
  script_mandatory_keys("Adobe/DNG/Converter/Win/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
adVer = "";

## Get version
if(!adVer = get_app_version(cpe:CPE)){
  exit(0);
}

# Check for vulnerable version 9.8 =~ 9.8.0.692
if(version_is_less(version:adVer, test_version:"9.8.0.692"))
{
  report = report_fixed_ver(installed_version:adVer, fixed_version:"9.8");
  security_message(data:report);
  exit(0);
}
