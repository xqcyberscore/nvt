###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_dos_vuln_oct15_macosx.nasl 6183 2017-05-22 09:03:43Z teissa $
#
# Adobe Shockwave Player Denial of Service Vulnerability Oct15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:shockwave_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806521");
  script_version("$Revision: 6183 $");
  script_cve_id("CVE-2015-7649");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-22 11:03:43 +0200 (Mon, 22 May 2017) $");
  script_tag(name:"creation_date", value:"2015-10-30 12:40:17 +0530 (Fri, 30 Oct 2015)");
  script_name("Adobe Shockwave Player Denial of Service Vulnerability Oct15 (Mac OS X)");

  script_tag(name: "summary" , value: "This host is installed with Adobe Shockwave
  Player and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw is due to a memory corruption
  vulnerability.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service.

  Impact Level: System/Application.");

  script_tag(name: "affected" , value:"Adobe Shockwave Player version before
  12.2.1.171 on Mac OS X.");

  script_tag(name: "solution" , value:"Upgrade to Adobe Shockwave Player version
  12.2.0.171 or later. For updates refer to http://get.adobe.com/shockwave");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name: "URL" , value : "https://helpx.adobe.com/security/products/shockwave/apsb15-26.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_adobe_shockwave_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Shockwave/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get version
if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:playerVer, test_version:"12.2.1.171"))
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + "12.2.1.171" + '\n';
  security_message(data:report);
  exit(0);
}
