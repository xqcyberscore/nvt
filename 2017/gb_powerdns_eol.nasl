###############################################################################
# OpenVAS Vulnerability Test
#
# PowerDNS End of Life Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113017");
  script_version("2019-06-25T08:56:36+0000");
  script_tag(name:"last_modification", value:"2019-06-25 08:56:36 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"creation_date", value:"2017-10-16 13:11:12 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("PowerDNS Products End of Life Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor_or_authoritative_server/installed");

  script_tag(name:"summary", value:"The version of the PowerDNS product on the remote host
  has reached the end of life and should not be used anymore.");

  script_tag(name:"impact", value:"An end of life version of a PowerDNS product is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise
  the security of this host.");

  script_tag(name:"solution", value:"Update the version of the PowerDNS product on the remote host to a still
  supported version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/authoritative/appendices/EOL.html");
  script_xref(name:"URL", value:"https://doc.powerdns.com/recursor/appendices/EOL.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("products_eol.inc");
include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:powerdns:authoritative_server", "cpe:/a:powerdns:recursor" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) )
  exit( 0 );

port = infos["port"];
cpe  = infos["cpe"];

if( ! infos = get_app_version_and_proto( cpe:cpe, port:port ) )
  exit( 0 );

version = infos["version"];
proto   = infos["proto"];

if( ret = product_reached_eol( cpe:cpe, version:version ) ) {

  if( "recursor" >< cpe )
    app = "PowerDNS Recursor";
  else if( "authoritative_server" >< cpe )
    app = "Authoritative Server";
  else
    app = "PowerDNS";

  report = build_eol_message( name:app,
                              cpe:cpe,
                              version:version,
                              eol_version:ret["eol_version"],
                              eol_date:ret["eol_date"],
                              eol_type:"prod" );

  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
