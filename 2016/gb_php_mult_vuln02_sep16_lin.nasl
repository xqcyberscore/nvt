###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln02_sep16_lin.nasl 5083 2017-01-24 11:21:46Z cfi $
#
# PHP Multiple Vulnerabilities - 02 - Sep16 (Linux)
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809319");
  script_version("$Revision: 5083 $");
  script_cve_id("CVE-2016-7124", "CVE-2016-7125", "CVE-2016-7126", "CVE-2016-7127",
                "CVE-2016-7128", "CVE-2016-7129", "CVE-2016-7130", "CVE-2016-7131",
		"CVE-2016-7132");
  script_bugtraq_id(92756, 92552, 92755, 92757, 92564, 92758);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:21:46 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-09-12 18:19:30 +0530 (Mon, 12 Sep 2016)");
  script_name("PHP Multiple Vulnerabilities - 02 - Sep16 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  - An invalid wddxPacket XML document that is mishandled in a wddx_deserialize
    call in 'ext/wddx/wddx.c' script.
  - An error in 'php_wddx_pop_element' function in 'ext/wddx/wddx.c' script.
  - An error in  'php_wddx_process_data' function in 'ext/wddx/wddx.c' script.
  - Improper handling of the case of a thumbnail offset that exceeds the file
    size in 'exif_process_IFD_in_TIFF' function in 'ext/exif/exif.c' script.
  - Improper validation of gamma values in 'imagegammacorrect' function
    in 'ext/gd/gd.c' script.
  - Improper validation of number of colors in 'imagegammacorrect' function
    in 'ext/gd/gd.c' script.
  - The script 'ext/session/session.c' skips invalid session names in a way that
    triggers incorrect parsing.
  - Improper handling of certain objects in 'ext/standard/var_unserializer.c'
    script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, to obtain sensitive information
  from process memory, to inject arbitrary-type session data by leveraging control
  of a session name.

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions prior to 5.6.25 and
  7.x before 7.0.10 on Linux");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.25, or 7.0.10,
  or later. For updates refer to http://www.php.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
phpPort = "";
phpVer = "";

## exit, if its not Linux
if(host_runs("Linux") != "yes") exit(0);

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

##check for version before 5.6.25
if(version_is_less(version:phpVer, test_version:"5.6.25"))
{
  fix = "5.6.25";
  VULN = TRUE;
}

## Check for version 7.0 before 7.0.10
else if(phpVer =~ "^(7\.0)")
{
  if(version_in_range(version:phpVer, test_version:"7.0", test_version2:"7.0.9"))
  {
    fix = "7.0.10";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);