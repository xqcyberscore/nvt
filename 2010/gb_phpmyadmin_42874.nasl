###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_42874.nasl 8926 2018-02-22 14:56:01Z cfischer $
#
# phpMyAdmin Debug Backtrace Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100775");
  script_version("$Revision: 8926 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-22 15:56:01 +0100 (Thu, 22 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)");
  script_bugtraq_id(42874);
  script_cve_id("CVE-2010-2958");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpMyAdmin Debug Backtrace Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42874");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-6.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.git.sourceforge.net/git/gitweb.cgi?p=phpmyadmin/phpmyadmin;a=commitdiff;h=133a77fac7d31a38703db2099a90c1b49de62e37");

  tag_summary = "phpMyAdmin is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied data.";

  tag_impact = "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may allow the attacker to steal cookie-based authentication
  credentials and to launch other attacks.";

  tag_affected = "Versions prior to phpMyAdmin 3.3.6 are vulnerable; other versions may
  also be affected.";

  tag_solution = "Vendor updates are available. Please see the references for more
  information.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3", test_version2:"3.3.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.3.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );