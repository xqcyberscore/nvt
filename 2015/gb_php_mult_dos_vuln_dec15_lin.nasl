###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_dos_vuln_dec15_lin.nasl 7546 2017-10-24 11:58:30Z cfischer $
#
# PHP Multiple Denial of Service Vulnerabilities - 01 - Dec15 (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806649");
  script_version("$Revision: 7546 $");
  script_cve_id("CVE-2015-7804", "CVE-2015-7803");
  script_bugtraq_id(76959);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:58:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-12-15 17:44:53 +0530 (Tue, 15 Dec 2015)");
  script_name("PHP Multiple Denial of Service Vulnerabilities - 01 - Dec15 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - An Off-by-one error in the 'phar_parse_zipfile' function within ext/phar/zip.c
    script.
  - An error in the 'phar_get_entry_data' function in ext/phar/util.c script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service (NULL pointer dereference and
  application crash).

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions before 5.5.30 and 5.6.x
  before 5.6.14");

  script_tag(name:"solution", value:"Upgrade to PHP 5.5.30 or 5.6.14 or
  later. For updates refer to http://www.php.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=70433");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/10/05/8");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

# Variable Initialization
phpPort = "";
phpVer = "";

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

## Check for version 5.6.x before 5.6.14
if(phpVer =~ "^(5\.6)")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.13"))
  {
    fix = "5.6.14";
    VULN = TRUE;
  }
}

##Check for version less 5.5.30
else if(version_is_less(version:phpVer, test_version:"5.5.30"))
{
  fix = "5.5.30";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + phpVer + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);