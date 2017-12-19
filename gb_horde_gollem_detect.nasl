###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_gollem_detect.nasl 8161 2017-12-18 16:10:24Z cfischer $
#
# Horde Gollem Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801869");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 8161 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-18 17:10:24 +0100 (Mon, 18 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Horde Gollem Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of Horde Gollem on remote host
  and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Get http port
port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir(make_list_unique( "/horde/gollem", "/gollem", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  ## Confirm the application
  if( ">File Manager Login<" >< rcvRes ) {

    version = "unknown";

    ## Send and Receive the response
    sndReq = http_get( item: dir + "/test.php", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:TRUE );

    ## Get the version
    ver = eregmatch( pattern:">Gollem: H. \(([0-9.]+)\)<", string:rcvRes );

    if( ver[1] == NULL ) {
      ## Get Version from CHANGES file
      sndReq = http_get( item: dir + "/docs/CHANGES", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:TRUE );
      ver = eregmatch( pattern:"v([0-9.]+)", string:rcvRes );
      if( ver[1] ) version = ver[1];
    } else {
      version = ver[1];
    }


    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/gollem", value:tmp_version );
    set_kb_item( name:"horde/gollem/installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:horde:gollem:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:horde:gollem';

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Horde Gollem",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version ),
                                              port:port );
    exit(0);
  }
}
exit( 0 );
