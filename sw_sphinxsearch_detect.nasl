###############################################################################
# OpenVAS Vulnerability Test
#
# Sphinx search server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111034");
  script_version("2019-09-12T07:47:19+0000");
  script_tag(name:"last_modification", value:"2019-09-12 07:47:19 +0000 (Thu, 12 Sep 2019)");
  script_tag(name:"creation_date", value:"2015-08-31 18:00:00 +0200 (Mon, 31 Aug 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sphinx search server Detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/sphinxql", 9306, "Services/sphinxapi", 9312);

  script_tag(name:"summary", value:"The script checks the presence of a Sphinx search server
  and sets the version in the kb.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("dump.inc");
include("misc_func.inc");

ports = get_ports_for_service( default_list:make_list( 9306 ), proto:"sphinxql" );

foreach port( ports ) {

  if( ! banner = get_kb_item( "sphinxsearch/" + port + "/sphinxql/banner" ) ) {

    soc = open_sock_tcp( port );
    if( ! soc )
      continue;

    send( socket:soc, data:"TEST\r\n" );

    buf = recv( socket:soc, length:64 );
    close( soc );
    if( ! buf )
      continue;

    banner = bin2string( ddata:buf, noprint_replacement:' ' );
    if( ! banner )
      continue;
  }

  # Examples:
  # 2.0.9-id64-release (rel20-r4115)
  # 2.1.2-id64-release (r4245)
  # 2.0.4-release (r3135)
  # 2.2.11-id64-release (95ae9a6)
  # 2.8.0 4006794b@190128 release
  # 3.0.2 e3d296ef@190531 release
  #
  # Binary:
  # 0x00:  4B 00 00 00 0A 32 2E 38 2E 30 20 34 30 30 36 37    K....2.8.0 40067
  # 0x10:  39 34 62 40 31 39 30 31 32 38 20 72 65 6C 65 61    94b@190128 relea
  # 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
  # 0x30:  08 82 21 02 00 00 00 00 00 00 00 00 00 00 00 00    ..!.............
  # 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00       ...............
  #
  # 0x00:  61 00 00 00 0A 33 2E 30 2E 32 20 65 33 64 32 39    a....3.0.2 e3d29
  # 0x10:  36 65 66 40 31 39 30 35 33 31 20 72 65 6C 65 61    6ef@190531 relea
  # 0x20:  73 65 00 01 00 00 00 01 02 03 04 05 06 07 08 00    se..............
  # 0x30:  08 82 21 02 00 08 00 15 00 00 00 00 00 00 00 00    ..!.............
  # 0x40:  00 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 00 6D    ...............m
  # 0x50:  79 73 71 6C 5F 6E 61 74 69 76 65 5F 70 61 73 73    ysql_native_pass
  # 0x60:  77 6F 72 64 00
  #
  # 0x00:  48 00 00 00 0A 32 2E 30 2E 38 2D 69 64 36 34 2D    H....2.0.8-id64-
  # 0x10:  72 65 6C 65 61 73 65 20 28 72 33 38 33 31 29 00    release (r3831).
  # 0x20:  01 00 00 00 01 02 03 04 05 06 07 08 00 08 82 21    ...............!
  # 0x30:  02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01    ................
  # 0x40:  02 03 04 05 06 07 08 09 0A 0B 0C 0D                ............
  #
  # nb: see find_service1.nasl as well
  if( version = eregmatch( string:banner, pattern:"^.\s{4}([0-9.]+)(-(id[0-9]+-)?release \([0-9a-z-]+\)| [0-9a-z]+@[0-9a-z]+ release)" ) ) {

    replace_kb_item( name:"sphinxsearch/" + port + "/sphinxql/banner", value:banner );

    install = port + "/tcp";

    register_service( port:port, proto:"sphinxql" );
    set_kb_item( name:"sphinxsearch/detected", value:TRUE );
    set_kb_item( name:"sphinxsearch/noauth", value:TRUE );
    set_kb_item( name:"sphinxsearch/" + port + "/detected", value:TRUE );
    set_kb_item( name:"sphinxsearch/" + port + "/noauth", value:TRUE );
    set_kb_item( name:"sphinxsearch/" + port + "/version", value:version[1] );

    cpe = build_cpe( value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:sphinxsearch:sphinxsearch:" );
    if( ! cpe )
      cpe = "cpe:/a:sphinxsearch:sphinxsearch";

    register_product( cpe:cpe, location:install, port:port, service:"sphinxql" );

    log_message( data:build_detection_report( app:"Sphinx search server",
                                              version:version[1],
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                 port:port );
  }
}

port = get_port_for_service( default:9312, proto:"sphinxapi" );

if( ! banner = get_kb_item( "sphinxsearch/" + port + "/sphinxapi/banner" ) ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    exit( 0 );

  send( socket:soc, data:"TEST\r\n\r\n" );

  buf = recv( socket:soc, length:64 );
  close( soc );
  if( ! buf )
    exit( 0 );

  banner = bin2string( ddata:buf, noprint_replacement:' ' );
  if( ! banner )
    exit( 0 );
}

# invalid command (code=12064, len=1414541105)
# nb: Don't use a ^ anchor, the banner is located within some binary blob.
# nb: see find_service1.nasl as well
if( banner = egrep( string:banner, pattern:"invalid command \(code=([0-9]+), len=([0-9]+)\)" ) ) {

  replace_kb_item( name:"sphinxsearch/" + port + "/sphinxapi/banner", value:banner );

  version = "unknown";
  install = port + "/tcp";

  register_service( port:port, proto:"sphinxapi" );
  set_kb_item( name:"sphinxsearch/detected", value:TRUE );
  set_kb_item( name:"sphinxsearch/noauth", value:TRUE );
  set_kb_item( name:"sphinxsearch/" + port + "/detected", value:TRUE );
  set_kb_item( name:"sphinxsearch/" + port + "/noauth", value:TRUE );
  set_kb_item( name:"sphinxsearch/" + port + "/version", value:version );

  cpe = "cpe:/a:sphinxsearch:sphinxsearch";

  register_product( cpe:cpe, location:install, port:port, service:"sphinxapi" );

  log_message( data:build_detection_report( app:"Sphinx search server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:banner ),
               port:port );
}

exit( 0 );
