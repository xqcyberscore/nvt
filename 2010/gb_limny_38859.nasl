###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_38859.nasl 4723 2016-12-09 07:05:28Z mwiegand $
#
# Limny 2.01 Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100545");
  script_version("$Revision: 4723 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-09 08:05:28 +0100 (Fri, 09 Dec 2016) $");
  script_tag(name:"creation_date", value:"2010-03-22 19:12:13 +0100 (Mon, 22 Mar 2010)");
  script_bugtraq_id(38859);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Limny 2.01 Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_limny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("limny/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38859");
  script_xref(name:"URL", value:"http://www.limny.org/");

  tag_summary = "Limny is prone to multiple remote vulnerabilities, including:

  - Multiple HTML-injection vulnerabilities
  - Multiple SQL-injection vulnerabilities
  - Multiple security-bypass vulnerabilities
  - Multiple cross-site scripting vulnerabilities.";

  tag_impact = "The attacker may exploit these issues to compromise the application,
  execute arbitrary code, steal cookie-based authentication credentials,
  gain unauthorized access to the application, modify data, or exploit
  latent vulnerabilities in the underlying database. Other attacks are
  also possible.";

  tag_affected = "Limny 2.01 is vulnerable; other versions may also be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"2.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
