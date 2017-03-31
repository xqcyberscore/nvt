###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_creative_cloud_apsb16-11_macosx.nasl 5527 2017-03-09 10:00:25Z teissa $
#
# Adobe Creative Cloud Security Updates APSB16-11 (MAC OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807672");
  script_version("$Revision: 5527 $");
  script_cve_id("CVE-2016-1034");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-09 11:00:25 +0100 (Thu, 09 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-18 16:13:45 +0530 (Mon, 18 Apr 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Creative Cloud Security Updates APSB16-11 (MAC OS X)");

  script_tag(name: "summary" , value:"This host is installed with Adobe Creative
  cloud and is prone to remote command execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"The flaw is due to a vulnerability in
  sync Process in the JavaScript API.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  attackers to read and write files on the client's file system.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Adobe Creative Cloud 3.6.0.244 before
  on MAC OS X.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Creative Cloud version
  3.6.0.244 or later.
  For updates refer https://www.adobe.com/creativecloud/desktop-app.html.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://helpx.adobe.com/security/products/creative-cloud/apsb16-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_macosx.nasl");
  script_mandatory_keys("AdobeCreativeCloud/MacOSX/Version");
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
if(version_is_less(version:cloudVer, test_version:"3.6.0.244"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"3.6.0.244");
  security_message(data:report);
  exit(0);
}
