###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_creative_cloud_apsb16-21_win.nasl 5513 2017-03-08 10:00:24Z teissa $
#
# Adobe Creative Cloud Security Updates APSB16-21 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808164");
  script_version("$Revision: 5513 $");
  script_cve_id("CVE-2016-4157", "CVE-2016-4158");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-08 11:00:24 +0100 (Wed, 08 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-06-16 12:06:19 +0530 (Thu, 16 Jun 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Updates APSB16-21 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Adobe Creative
  cloud and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"The multiple flaws are due to,
  - An errot  in the directory search path used to find resources.
  - An unquoted service path enumeration vulnerability.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  attackers to gain elevated privileges and leads to code execution.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Adobe Creative Cloud before 3.7.0.272
  on Windows.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Creative Cloud version
  3.7.0.272 or later.
  For updates refer https://www.adobe.com/creativecloud/desktop-app.html.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://helpx.adobe.com/security/products/creative-cloud/apsb16-21.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
cloudVer = "";

## Get version
if(!cloudVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check Adobe Creative Cloud vulnerable version
if(version_is_less(version:cloudVer, test_version:"3.7.0.272"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"3.7.0.272");
  security_message(data:report);
  exit(0);
}
