###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_41963.nasl 9220 2018-03-27 12:19:39Z cfischer $
#
# Apache HTTP Server Multiple Remote Denial of Service Vulnerabilities
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100725");
  script_version("$Revision: 9220 $");
  script_cve_id("CVE-2010-1452");
  script_bugtraq_id(41963);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-03-27 14:19:39 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name:"creation_date", value:"2010-07-27 20:48:46 +0200 (Tue, 27 Jul 2010)");
  script_name("Apache HTTP Server Multiple Remote Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/41963");
  script_xref(name:"URL", value:"http://httpd.apache.org/download.cgi");
  script_xref(name:"URL", value:"http://httpd.apache.org/");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_xref(name:"URL", value:"http://www.apache.org/dist/httpd/CHANGES_2.2.16");

  tag_summary = "Apache HTTP Server is prone to multiple remote denial-of-service
  vulnerabilities.";

  tag_impact = "An attacker can exploit these issues to deny service to
  legitimate users.";

  tag_affected = "Versions prior to Apache 2.2.16 are vulnerable.";

  tag_solution = "These issues have been fixed in Apache 2.2.16. Please see the
  references for more information.";

  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.2", test_version2:"2.2.15" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.16" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );