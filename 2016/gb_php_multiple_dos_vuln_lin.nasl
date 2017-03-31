###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_multiple_dos_vuln_lin.nasl 5083 2017-01-24 11:21:46Z cfi $
#
# PHP Multiple Denial of Service Vulnerabilities (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808611");
  script_version("$Revision: 5083 $");
  script_cve_id("CVE-2015-8877", "CVE-2015-8879", "CVE-2015-8874");
  script_bugtraq_id(90866, 90842, 90714);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:21:46 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP Multiple Denial of Service Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  - An improper handling of driver behavior for SQL_WVARCHAR columns in the
    'odbc_bindcols function' in 'ext/odbc/php_odbc.c' script.
  - The 'gdImageScaleTwoPass' function in gd_interpolation.c script in the 
    GD Graphics Library uses inconsistent allocate and free approaches.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (application crash or
  memory consuption).

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions prior to 5.6.12 on Linux");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.12
  or later. For updates refer to http://www.php.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

## Check for version before 5.6.12
if(version_is_less(version:phpVer, test_version:"5.6.12"))
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.6.12");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);