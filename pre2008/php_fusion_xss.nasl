###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_fusion_xss.nasl 5668 2017-03-21 14:16:34Z cfi $
#
# PHP-Fusion homepage address XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>  
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
###############################################################################

CPE = "cpe:/a:php-fusion:php-fusion";

#  Ref: Espen Andersson

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15392");
  script_version("$Revision: 5668 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-21 15:16:34 +0100 (Tue, 21 Mar 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("PHP-Fusion homepage address XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-fusion/installed");

  tag_summary = "A vulnerability exists in the remote version of PHP-Fusion that may
  allow an attacker to execute arbitrary HTML and script code in the context of the user's browser.";

  tag_solution = "Apply the patch for 4.01.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.00" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.01" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );