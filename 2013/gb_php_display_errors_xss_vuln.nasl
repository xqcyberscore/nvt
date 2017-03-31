###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_display_errors_xss_vuln.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# PHP 'display_errors' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803778");
  script_version("$Revision: 5351 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2013-11-26 13:02:20 +0530 (Tue, 26 Nov 2013)");
  script_name("PHP 'display_errors' Cross Site Scripting Vulnerability");

  tag_summary = "This host is installed with PHP and is prone to cross site scripting
  vulnerability.";

  tag_vuldetect = "Get the installed version of PHP with the help of detect NVT and check
  the version is vulnerable or not.";

  tag_insight = "The flaw is due to an error in handling 'display_errors', when display_errors
  is set to on and html_errors is set to on.";

  tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.

  Impact Level: Application";

  tag_affected = "PHP versions 5.3.10 and 5.4.0";

  tag_solution = "Upgrade to latest version of PHP,
  http://www.php.net/downloads.php";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/111695/");
  script_xref(name:"URL", value:"http://dl.packetstormsecurity.net/1204-exploits/php-xss.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

## check the version
if(version_is_equal(version:phpVer, test_version:"5.3.10") ||
   version_is_equal(version:phpVer, test_version:"5.4.0")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.11/5.4.1");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
