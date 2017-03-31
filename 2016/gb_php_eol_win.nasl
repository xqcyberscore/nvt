###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_eol_win.nasl 5083 2017-01-24 11:21:46Z cfi $
#
# PHP End Of Life Detection (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105888");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 5083 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:21:46 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-09-15 07:00:00 +0200 (Thu, 15 Sep 2016)");
  script_name("PHP End Of Life Detection (Windows)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://secure.php.net/supported-versions.php");

  tag_summary = "The PHP version on the remote host has reached the end of life and should
  not be used anymore.";

  tag_impact = "An end of life version of PHP is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.";

  tag_insight = "Each release branch of PHP is fully supported for two years from its initial stable release.
  During this period, bugs and security issues that have been reported are fixed and are released in regular point releases.

  After this two year period of active support, each branch is then supported for an additional year for critical security
  issues only. Releases during this period are made on an as-needed basis: there may be multiple point releases, or none,
  depending on the number of reports.

  Once the three years of support are completed, the branch reaches its end of life and is no longer supported.";

  tag_solution = "Update the PHP version on the remote host to a still supported version.";

  tag_affected = "PHP versions below PHP 5.6";

  tag_vuldetect = "Get the installed version with the help of the detect NVT and check if the version is unsupported.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"vuldetect", value:tag_vuldetect);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( host_runs( "Windows" ) != "yes" ) exit( 0 );

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Check https://secure.php.net/supported-versions.php and update this
if( version_is_less( version:vers, test_version:"5.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.6/7.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
