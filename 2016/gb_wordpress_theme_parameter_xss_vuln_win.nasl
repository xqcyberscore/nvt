###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_theme_parameter_xss_vuln_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# WordPress 'theme' Parameter Cross Site Scripting Vulnerability Jan16 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807030");
  script_version("$Revision: 7545 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-01-18 14:20:15 +0530 (Mon, 18 Jan 2016)");
  script_name("WordPress 'theme' Parameter Cross Site Scripting Vulnerability Jan16 (Windows)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient
  validation of user supplied inpu via 'theme' parameter to
  'customize.php' script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to create a specially crafted request that would execute
  arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.

  Impact Level: Application");

  script_tag(name:"affected", value:"WordPress versions 3.7.x, through 3.7.11,
  3.8.x through 3.8.11, 3.9.x through 3.9.9, 4.0.x through 4.0.8, 4.1.x through
  4.1.8, 4.2.x through 4.2.5 and 4.3.x through 4.3.1 and 4.4 on Windows.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 3.7.12 or
  3.8.12 or 3.9.10 or 4.0.9 or 4.1.9 or 4.2.6 or 4.3.2 or 4.4.1 or later,
  For updates refer to https://wordpress.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://wpvulndb.com/vulnerabilities/8358");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
wpPort = "";
wpVer = "";

## get the port
if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

## Check for version
if(version_in_range(version:wpVer, test_version:"3.7", test_version2:"3.7.11"))
{
  fix = "3.7.12";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"3.8", test_version2:"3.8.11"))
{
  fix = "3.8.12";
  VULN = TRUE;
}

else if(version_in_range(version:wpVer, test_version:"3.9", test_version2:"3.9.9"))
{
  fix = "3.9.10";
  VULN = TRUE;
}

else if(version_in_range(version:wpVer, test_version:"4.0", test_version2:"4.0.8"))
{
  fix = "4.0.9";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.1", test_version2:"4.1.8"))
{
  fix = "4.1.9";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.2", test_version2:"4.2.5"))
{
  fix = "4.2.6";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.3", test_version2:"4.3.1"))
{
  fix = "4.3.2";
  VULN = TRUE;
}
else if(version_is_equal(version:wpVer, test_version:"4.4"))
{
  fix = "4.4.1";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + wpVer + '\n' +
           'Fixed Version:     ' + fix + '\n';

  security_message(data:report, port:wpPort);
  exit(0);
}
