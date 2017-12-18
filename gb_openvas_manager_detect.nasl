###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_manager_detect.nasl 8137 2017-12-15 11:26:42Z cfischer $
#
# OpenVAS Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103825");
  script_version("$Revision: 8137 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:26:42 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-11-08 12:24:10 +0100 (Fri, 08 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenVAS Manager Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service3.nasl");
  script_require_ports("Services/openvas-manager", 9390);

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  determine if it is a OpenVAS Manager");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:9390 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:'<foo/>\r\n' );
ret = recv( socket:soc, length:256 );
close( soc );

if( "omp_response" >< ret && "GET_VERSION" >< ret ) {

  set_kb_item( name:"openvas_manager/installed", value:TRUE );
  set_kb_item( name:"openvas_framework_component/installed", value:TRUE );

  manager_version = "unknown";
  omp_version = "unknown";
  install = port + "/tcp";
  concluded = ret;

  soc = open_sock_tcp( port );
  if( soc ) {
    send( socket:soc, data:'<get_version/>\r\n' );
    ret = recv( socket:soc, length:256 );
    close( soc );

    ver = eregmatch( pattern:"<version>([0-9.]+)</version>", string:ret );
    if( ver[1] ) {
      concluded = "OMP protocol version request: " + ver[0];
      omp_version = ver[1];
      # We can fingerprint the major OpenVAS Manager version from the supported OMP protocol version.
      # The OMP protocol version is currently matching the OpenVAS Manager protocol but that could change.
      # http://www.openvas.org/protocol-doc.html
      if( omp_version == "7.0" ) {
        manager_version = "7.0";
      } else if( omp_version == "6.0" ) {
        manager_version = "6.0";
      } else if( omp_version == "5.0" ) {
        manager_version = "5.0";
      } else if( omp_version == "4.0" ) {
        manager_version = "4.0";
      } else if( omp_version == "3.0" ) {
        manager_version = "3.0";
      } else if( omp_version == "2.0" ) {
        manager_version = "2.0";
      } else if( omp_version == "1.0" ) {
        manager_version = "1.0";
      }
    }
  }

  cpe = build_cpe( value:manager_version, exp:"^([0-9.]+)", base:"cpe:/a:openvas:openvas_manager:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:openvas:openvas_manager";

  register_service( port:port, proto:"openvas-manager" );
  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"OpenVAS Manager",
                                            version:manager_version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );
