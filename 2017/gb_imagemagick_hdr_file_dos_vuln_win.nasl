###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_hdr_file_dos_vuln_win.nasl 5536 2017-03-10 13:04:45Z antu123 $
#
# ImageMagick HDR File Processing Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810582");
  script_version("$Revision: 5536 $");
  script_cve_id("CVE-2015-8900");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-10 14:04:45 +0100 (Fri, 10 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-03-09 12:18:46 +0530 (Thu, 09 Mar 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick HDR File Processing Denial of Service Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with ImageMagick
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to an HDR file processing
  error in the 'ReadHDRImage' function in 'coders/hdr.c' script.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  remote attackers to cause a denial of service condition.

  Impact Level: Application");

  script_tag(name: "affected" , value:"ImageMagick versions 6.x and 7.x
  on Windows.");

  script_tag(name: "solution" , value:"No solution or patch is available as
  of 9th March, 2017. Information regarding this issue will be updated
  once the solution details are available. For updates refer to
  http://www.imagemagick.org");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2015/02/26/13");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=1195260");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
imVer = "";
report = "";

## Get version
if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(imVer =~ "^(7|6)\.")
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'NoneAvailable');
  security_message(data:report);
  exit(0);
}
