###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpmyadmin_cve_2009_1285.nasl 8916 2018-02-22 07:55:37Z cfischer $
#
# phpMyAdmin 'CVE-2009-1285' Configuration File PHP Code Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100144");
  script_version("$Revision: 8916 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-22 08:55:37 +0100 (Thu, 22 Feb 2018) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_bugtraq_id(34526);
  script_cve_id("CVE-2009-1285");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpMyAdmin 'CVE-2009-1285' Configuration File PHP Code Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34526");

  tag_summary = "According to its version number, the remote version of phpMyAdmin is
  prone to a remote PHP code-injection vulnerability.";

  tag_impact = "An attacker can exploit this issue to inject and execute arbitrary
  malicious PHP code in the context of the webserver process. This may
  facilitate a compromise of the application and the underlying
  system; other attacks are also possible.";

  tag_affected = "phpMyAdmin 3.x versions prior to 3.1.3.2 are vulnerable.";

  tag_solution = "Vendor updates are available. Please see http://www.phpmyadmin.net for more
  Information.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3", test_version2:"3.1.3.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );