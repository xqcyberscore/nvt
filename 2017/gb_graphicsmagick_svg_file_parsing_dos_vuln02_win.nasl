###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_svg_file_parsing_dos_vuln02_win.nasl 8209 2017-12-21 08:12:18Z cfischer $
#
# GraphicsMagick 'SVG File Parsing' Denial of Service Vulnerability-02 (Windows)
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

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810540");
  script_version("$Revision: 8209 $");
  script_cve_id("CVE-2016-2317");
  script_bugtraq_id(83241);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 09:12:18 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-02-07 19:04:50 +0530 (Tue, 07 Feb 2017)");
  script_name("GraphicsMagick 'SVG File Parsing' Denial of Service Vulnerability-02 (Windows)");

  script_tag(name: "summary" , value:"This host is installed with GraphicsMagick
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to heap and stack buffer 
  overflow errors in TracePoint function in magick/render.c, GetToken function 
  in magick/utility.c, and GetTransformTokens function in coders/svg.c related 
  with the parsing and processing of SVG files.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote 
  attackers to cause a denial of service via a crafted SVG file.

  Impact Level: Application");

  script_tag(name: "affected" , value:"GraphicsMagick versions 1.3.23 and 
  1.3.24 on Windows");

  script_tag(name: "solution" , value: "Upgrade to version 1.3.25 or later. 
  For updates refer to http://www.graphicsmagick.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2016/05/31/3");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2016/q1/297");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
gmVer = "";

## Get the version
if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(gmVer =~ "^1\.3\.")
{
  ## Check the version is prior to 1.3.25
  if(version_in_range(version:gmVer, test_version:"1.3.23", test_version2:"1.3.24"))
  {
    report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.25");
    security_message(data:report);
    exit(0);
  }
}

exit(0);
