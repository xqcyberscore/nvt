###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_dng_converter_memory_corruption_vuln_nov17_win.nasl 7790 2017-11-16 13:11:14Z santu $
#
# Adobe DNG Converter Memory Corruption Vulnerability Nov17 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:adobe:dng_converter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812211");
  script_version("$Revision: 7790 $");
  script_cve_id("CVE-2017-11295");
  script_bugtraq_id(101828);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-11-16 14:11:14 +0100 (Thu, 16 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-16 16:38:07 +0530 (Thu, 16 Nov 2017)");
  script_name("Adobe DNG Converter Memory Corruption Vulnerability Nov17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe DNG
  Converter and is prone to a memory corruption vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to some unspecified memory
  corruption error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to
  execute arbitrary code in the context of the user running the affected application.
  Failed exploit attempts will likely result in denial-of-service conditions.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Adobe DNG Converter 9.12.1 and earlier 
  versions on Windows");

  script_tag(name:"solution", value:"Upgrade to Adobe DNG Converter version 10.0
  or later. For updates refer to http://supportdownloads.adobe.com.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/dng-converter/apsb17-37.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_dng_converter_detect_win.nasl");
  script_mandatory_keys("Adobe/DNG/Converter/Win/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

adVer = "";
path = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
adVer = infos['version'];
path = infos['location'];

# Check for vulnerable versions, 9.12.1 = 9.12.1.790
if(version_is_less_equal(version:adVer, test_version:"9.12.1.790"))
{
  report = report_fixed_ver( installed_version:adVer, fixed_version:"10.0", install_path:path );
  security_message(data:report);
  exit(0);
}
