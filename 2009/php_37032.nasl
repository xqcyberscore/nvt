###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_37032.nasl 4505 2016-11-14 15:16:47Z cfi $
#
# PHP 'symlink()' 'open_basedir' Restriction Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100352");
  script_version("$Revision: 4505 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-14 16:16:47 +0100 (Mon, 14 Nov 2016) $");
  script_tag(name:"creation_date", value:"2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)");
  script_bugtraq_id(37032);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("PHP 'symlink()' 'open_basedir' Restriction Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37032");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/70");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_exploitalert/14");
  script_xref(name:"URL", value:"http://www.php.net/");

  tag_summary = "PHP is prone to an 'open_basedir' restriction-bypass vulnerability
  because of a design error.";

  tag_impact = "Successful exploits could allow an attacker to read and write files in
  unauthorized locations.";

  tag_insight = "This vulnerability would be an issue in shared-hosting configurations
  where multiple users can create and execute arbitrary PHP script code.
  In such cases, 'open_basedir' restrictions are expected to isolate
  users from each other.";

  tag_affected = "PHP 5.2.11 and 5.3.0 are vulnerable; other versions may also be
  affected.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"5.2.11" ) ||
    version_is_equal( version:vers, test_version:"5.3.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );