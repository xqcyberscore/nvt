###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_eol_win.nasl 7539 2017-10-24 08:52:47Z cfischer $
#
# IBM Domino End of Life Detection (Windows)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113034");
  script_version("$Revision: 7539 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 10:52:47 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-16 14:57:58 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Domino End of Life Detection (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_lotus_domino_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Domino/Installed", "Host/runs_windows");

  tag_summary = "The IBM Domino version on the remote host has reached the end of life and should not be used anymore.";

  tag_impact = "An end of life version of IBM Domino is not receiving any security updates from the vendor. Unfixed security vulnerabilities
    might be leveraged by an attacker to compromise the security of this host.";

  tag_solution = "Update the IBM Domino version on the remote host to a still supported version.";

  tag_vuldetect = "Get the installed version with the help of the detection NVT and check if the version is unsupported.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"vuldetect", value:tag_vuldetect);

  script_xref(name:"URL", value:"https://www-01.ibm.com/software/support/lifecycleapp/PLCSearch.wss?q=lotus+domino&ibm-search=Search");

  exit( 0 );
}

CPE = "cpe:/a:ibm:lotus_domino";

include( "misc_func.inc" );
include( "products_eol.inc" );
include( "version_func.inc" );
include( "host_details.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( ret = product_reached_eol( cpe: CPE, version: version ) ) {
  report = build_eol_message( name: "IBM Domino",
                              cpe: CPE,
                              version: version,
                              eol_version: ret["eol_version"],
                              eol_date: ret["eol_date"],
                              eol_type: "prod" );

  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
