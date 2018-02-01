###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailman_xss_vuln.nasl 8605 2018-01-31 12:57:41Z jschulte $
#
# Mailman before 2.1.26 XSS Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113097");
  script_version("$Revision: 8605 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 13:57:41 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-31 13:35:40 +0100 (Wed, 31 Jan 2018)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-5950");

  script_name("Mailman before 2.1.26 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"Cross-site scripting (XSS) vulnerability in the web UI in Mailman.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to inject arbitrary web script or HTML.");
  script_tag(name:"affected", value:"GNU Mailman before 2.1.26");
  script_tag(name:"solution", value:"Update to version 2.1.26 or above.");

  script_xref(name:"URL", value:"https://www.mail-archive.com/mailman-users@python.org/msg70375.html");

  exit( 0 );
}

include( "host_details.inc" );
include( "version_func.inc" );
include( "http_func.inc" );

port = get_http_port( default: 80 );

if( ! version_string = get_kb_item( string( "www/", port, "/Mailman" ) ) ) exit( 0 );
if( ! matches = eregmatch( string: version_string, pattern: "^(.+) under (/.*)$" ) ) exit( 0 );

version = matches[1];

if( ! isnull( version ) && version >!< "unknown") {
  if( version_is_less( version: version, test_version: "2.1.26" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "2.1.26" );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
