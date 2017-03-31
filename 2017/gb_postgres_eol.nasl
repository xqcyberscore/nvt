###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgres_eol.nasl 5294 2017-02-14 15:05:25Z mime $
#
# PostgreSQL End Of Life Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140158");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 5294 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-14 16:05:25 +0100 (Tue, 14 Feb 2017) $");
  script_tag(name:"creation_date", value:"2017-02-14 13:48:20 +0100 (Tue, 14 Feb 2017)");
  script_name("PostgreSQL End Of Life Detection");
  script_summary("Determine if the PostgreSQL version on the remote host has reached the end of life");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl");
  script_mandatory_keys("PostgreSQL/installed");
  script_require_ports("Services/postgresql", 5432);

  script_xref(name:"URL", value:"https://www.postgresql.org/support/versioning/");

  tag_summary = "The PostgreSQL version on the remote host has reached the end of life and should
  not be used anymore.";

  tag_impact = "An end of life version of PostgreSQL is not receiving any security updates from the vendor. Unfixed security vulnerabilities
  might be leveraged by an attacker to compromise the security of this host.";

  tag_solution = "Update the PostgreSQL version on the remote host to a still supported version.";

  tag_vuldetect = "Get the installed version with the help of the detect NVT and check if the version is unsupported.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"vuldetect", value:tag_vuldetect);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ret = product_reached_eol( cpe:CPE, version:version ) )
{
  report = 'The PostgreSQL version has reached the end of life.\n\n' + 
           'Installed version: ' + version + '\n' +
           'EOL version:       ' + ret['eol_version'] + '\n' +
           'EOL date:          ' + ret['eol_date'] + '\n';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
