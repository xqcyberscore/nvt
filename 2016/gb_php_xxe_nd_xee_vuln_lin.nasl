###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_xxe_nd_xee_vuln_lin.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# PHP XML Entity Expansion And XML External Entity Vulnerabilities (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.808615");
  script_version("$Revision: 7585 $");
  script_cve_id("CVE-2015-8866");
  script_bugtraq_id(87470);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_name("PHP XML Entity Expansion And XML External Entity Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to XML entity expansion and XML external entity vulnerabilities");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to script 'ext/libxml/libxml.c'
  does not isolate each thread from 'libxml_disable_entity_loader' when 
  PHP-FPM is used.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to conduct XML External Entity (XXE) and XML Entity
  Expansion (XEE) attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"PHP versions prior to 5.5.22 and 5.6.x
  before 5.6.6 on Linux");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.5.22, or 5.6.6, 
  or later. For updates refer to http://www.php.net");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

## Check for version before 5.5.22
if(version_is_less(version:phpVer, test_version:"5.5.22"))
{
  fix = '5.5.22';
  VULN = TRUE;
}

## Check for version 5.6.x before 5.6.6
else if(phpVer =~ "^(5\.6)")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.5"))
  {
    fix = '5.6.6';
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