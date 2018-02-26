###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_setup_script_xss_vuln.nasl 8926 2018-02-22 14:56:01Z cfischer $
#
# phpMyAdmin Setup Script Request Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801286");
  script_version("$Revision: 8926 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-22 15:56:01 +0100 (Thu, 22 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-3263");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpMyAdmin Setup Script Request Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41210");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61675");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-7.php");

  tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected site.

  Impact Level: Application";

  tag_affected = "phpMyAdmin versions 3.x before 3.3.7";

  tag_insight = "The flaw is caused by an unspecified input validation error when processing
  spoofed requests sent to setup script, which could be exploited by attackers
  to cause arbitrary scripting code to be executed on the user's browser session
  in the security context of an affected site.";

  tag_solution = "Upgrade to phpMyAdmin version 3.3.7 or later,

  For updates refer to http://www.phpmyadmin.net/home_page/downloads.php";

  tag_summary = "The host is running phpMyAdmin and is prone to Cross-Site Scripting
  Vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
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

if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.3.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.3.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );