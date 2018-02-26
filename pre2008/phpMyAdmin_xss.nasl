##############################################################################
# OpenVAS Vulnerability Test
# $Id: phpMyAdmin_xss.nasl 8931 2018-02-23 07:42:47Z cfischer $
#
# phpMyAdmin XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

#  Ref: Cedric Cochin

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15770");
  script_version("$Revision: 8931 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-23 08:42:47 +0100 (Fri, 23 Feb 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11707); 
  script_cve_id("CVE-2004-1055");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpMyAdmin XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  tag_summary = "The remote host is running phpMyAdmin, an open-source software
  written in PHP to handle the administration of MySQL over the Web.

  This version is vulnerable to cross-site scripting attacks through
  read_dump.php script.";

  tag_impact = "With a specially crafted URL, an attacker can cause arbitrary
  code execution resulting in a loss of integrity.";

  tag_solution = "Upgrade to version 2.6.0-pl3 or newer";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ereg( pattern:"^(2\.[0-5]\..*|2\.6\.0|2\.6\.0-pl[12])", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6.0-pl3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );