###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_use_after_free_vuln02_july15_win.nasl 2015-07-23 13:10:57 July$
#
# PHP Use-After-Free Denial Of Service Vulnerability - 02 - Jul15 (Windows)
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805691");
  script_version("$Revision: 5082 $");
  script_cve_id("CVE-2015-1351");
  script_bugtraq_id(71929);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:14:23 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2015-07-23 13:10:57 +0530 (Thu, 23 Jul 2015)");
  script_name("PHP Use-After-Free Denial Of Service Vulnerability - 02 - Jul15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to Use-after-free
  vulnerability in the '_zend_shared_memdup' function in 'zend_shared_alloc.c'
  script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service or possibly have unspecified
  other impact.

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions through 5.6.7 and 5.5.x before
  5.5.25");

  script_tag(name:"solution", value:"Upgrade to PHP 5.5.22 or 5.6.6 or later.
  For updates refer to http://www.php.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://bugzilla.redhat.com/show_bug.cgi?id=1185900");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/01/24/9");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
phpPort = "";
phpVer = "";

## exit, if its Windows
if(host_runs("Windows") != "yes") exit(0);

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

## Check for version 5.6.x before 5.6.8
if(phpVer =~ "^(5\.6)")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.7"))
  {
    fix = '5.6.8';
    VULN = TRUE;
  }
}

## Check for version 5.5.x before 5.5.25
if(phpVer =~ "^(5\.5)")
{
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.24"))
  {
    fix = '5.5.25';
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed Version: ' + phpVer + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);