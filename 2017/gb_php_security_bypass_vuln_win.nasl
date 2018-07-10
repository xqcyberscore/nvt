###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_security_bypass_vuln_win.nasl 10454 2018-07-09 05:32:41Z cfischer $
#
# PHP 'URL checks' Security Bypass Vulnerability Jul17 (Windows)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811488");
  script_version("$Revision: 10454 $");
  script_cve_id("CVE-2016-10397");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-07-09 07:32:41 +0200 (Mon, 09 Jul 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 16:38:21 +0530 (Thu, 13 Jul 2017)");
  script_name("PHP 'URL checks' Security Bypass Vulnerability Jul17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to incorrect handling of
  various URI components in the URL parser.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  an attacker to bypass hostname-specific URL checks.

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions before 5.6.28, 7.x before 7.0.13");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.28, 7.0.13,
  or later. For updates refer to http://www.php.net");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpport = get_app_port(cpe:CPE))){
  exit(0);
}

if(! vers = get_app_version(cpe:CPE, port:phpport)){
  exit(0);
}

if(version_is_less(version:vers, test_version:"5.6.28")){
  fix = "5.6.28";
}

else if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.12")){
  fix = "7.0.13";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:phpport, data:report);
  exit(0);
}
exit(99);