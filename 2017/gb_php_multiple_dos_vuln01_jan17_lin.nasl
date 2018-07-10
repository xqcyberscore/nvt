###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_multiple_dos_vuln01_jan17_lin.nasl 10454 2018-07-09 05:32:41Z cfischer $
#
# PHP Multiple Denial of Service Vulnerabilities - 01 - Jan17 (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108052");
  script_version("$Revision: 10454 $");
  script_cve_id("CVE-2016-10161", "CVE-2016-10158");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 07:32:41 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)");
  script_name("PHP Multiple Denial of Service Vulnerabilities - 01 - Jan17 (Linux)");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - The exif_convert_any_to_int function in ext/exif/exif.c tries to divide
  the minimum representable negative integer by -1.

  - A mishandled serialized data in a finish_nested_data call within the
  object_common1 function in ext/standard/var_unserializer.c.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (buffer over-read or application crash).

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions before 5.6.30, 7.0.x before
  7.0.15, and 7.1.x before 7.1.1.");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.30, 7.0.15, 7.1.1
  or later. For updates refer to http://www.php.net");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.6.30" ) ) {
  vuln = TRUE;
  fix = "5.6.30";
}

if( version_in_range( version:vers, test_version:"7.0", test_version2:"7.0.14" ) ) {
  vuln = TRUE;
  fix = "7.0.15";
}

if( vers =~ "^7\.1") {
  if( version_is_less( version:vers, test_version:"7.1.1" ) ) {
    vuln = TRUE;
    fix = "7.1.1";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );