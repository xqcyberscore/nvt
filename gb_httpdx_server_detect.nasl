###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_server_detect.nasl 8146 2017-12-15 13:40:59Z cfischer $
#
# httpdx Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800960");
  script_version("$Revision: 8146 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:40:59 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("httpdx Server Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", "Services/ftp", 80, 21);

  script_tag(name:"summary", value:"Detection of httpdx Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("http_func.inc");
include("host_details.inc");

ftpPorts = get_kb_list( "Services/ftp" );
if( ! ftpPorts ) ftpPorts = make_list( 21 );

foreach port( ftpPorts ) {

  if( get_port_state( port ) ) {

    banner = get_ftp_banner( port:port );
    if( banner && "httpdx" >< banner ) {
      vers = "unknown";
      httpdxVer = eregmatch( pattern:"httpdx.([0-9.]+[a-z]?)", string:banner );
      if( ! isnull( httpdxVer[1] ) ) {
        set_kb_item( name:"httpdx/" + port + "/Ver", value:httpdxVer[1] );
        vers = httpdxVer[1];
      }

      set_kb_item( name:"httpdx/installed", value:TRUE );

      ## build cpe and store it as host_detail
      cpe = build_cpe( value:vers, exp:"^([0-9.]+([a-z]+)?)", base:"cpe:/a:jasper:httpdx:" );
      if( isnull( cpe ) )
        cpe = 'cpe:/a:jasper:httpdx';

      register_product( cpe:cpe, location:"/", port:port, service:"ftp" );

      log_message( data:build_detection_report( app:"httpdx",
                                                version:vers,
                                                install:"/",
                                                cpe:cpe,
                                                concluded:httpdxVer[0] ),
                                                port:port );
    }
  }
}

if( get_kb_item( "Settings/disable_cgi_scanning" ) ) exit( 0 );

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( banner && "httpdx" >< banner ) {
  vers = "unknown";
  httpdxVer = eregmatch( pattern:"httpdx.([0-9.]+[a-z]?)", string:banner );
  if( ! isnull( httpdxVer[1] ) ) {
    set_kb_item( name:"httpdx/" + port + "/Ver", value:httpdxVer[1] );
    vers = httpdxVer[1];
  }

  set_kb_item( name:"httpdx/installed", value:TRUE );

  ## build cpe and store it as host_detail
  cpe = build_cpe( value:vers, exp:"^([0-9.]+([a-z]+)?)", base:"cpe:/a:jasper:httpdx:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:jasper:httpdx';

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  log_message( data:build_detection_report( app:"httpdx",
                                            version:vers,
                                            install:"/",
                                            cpe:cpe,
                                            concluded:httpdxVer[0] ),
                                            port:port );
}

exit( 0 );