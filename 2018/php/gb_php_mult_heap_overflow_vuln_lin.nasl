###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_heap_overflow_vuln_lin.nasl 11771 2018-10-08 05:52:02Z asteins $
#
# PHP Multiple Heap Buffer Overflow Vulnerabilities (Linux)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813901");
  script_version("$Revision: 11771 $");
  script_cve_id("CVE-2018-14851");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-08 07:52:02 +0200 (Mon, 08 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 13:28:46 +0530 (Tue, 07 Aug 2018)");
  script_name("PHP Multiple Heap Buffer Overflow Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  -'exif_process_IFD_in_MAKERNOTE()' in exif.c file suffers from
    improper validation against crafted JPEG files.

  - 'exif_thumbnail_extract()' function in exif.c file suffers from improper
    validation of length of 'ImageInfo->Thumbnail.offset + ImageInfo->Thumbnail.size'");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause heap overflow and denial of service.

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions before 5.6.37, 7.0.x before 
  7.0.31, 7.1.x before 7.1.20, and 7.2.x before 7.2.8 on Linux.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.37, 7.0.31, 
  7.1.20 or 7.2.8 or later. For updates refer to Reference links.");

  script_xref(name:"URL", value:"http://www.php.net");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76557");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76423");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpPort = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:phpPort, exit_no_version:TRUE)) exit(0);
phpVers = infos['version'];
path = infos['location'];

if(version_is_less(version:phpVers, test_version:"5.6.37")){
  fix = "5.6.37";
}

else if(version_in_range(version:phpVers, test_version:"7.0", test_version2:"7.0.30")){
  fix = "7.0.31";
}

else if(version_in_range(version:phpVers, test_version:"7.1", test_version2:"7.1.19")){
  fix = "7.1.20";
}

else if(version_in_range(version:phpVers, test_version:"7.2", test_version2:"7.2.7")){
  fix = "7.2.8";
}

if(fix)
{
  report = report_fixed_ver(installed_version:phpVers, fixed_version:fix, install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}
