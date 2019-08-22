# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112358");
  script_version("2019-08-22T07:49:23+0000");
  script_cve_id("CVE-2018-1000225", "CVE-2018-1000226");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-22 07:49:23 +0000 (Thu, 22 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-08-21 09:48:12 +0200 (Tue, 21 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cobbler <= 2.6.11+ Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Cobbler and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws consist of a persistent XSS vulnerability and an incorrect authentication vulnerability.");

  script_tag(name:"affected", value:"Cobbler versions up to and including 2.6.11.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://movermeyer.com/2018-08-02-privilege-escalation-exploits-in-cobblers-api/");
  script_xref(name:"URL", value:"https://github.com/cobbler/cobbler/issues/1916");
  script_xref(name:"URL", value:"https://github.com/cobbler/cobbler/issues/1917");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_cobbler_detect.nasl");
  script_mandatory_keys("Cobbler/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

CPE = "cpe:/a:michael_dehaan:cobbler";

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.6.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
