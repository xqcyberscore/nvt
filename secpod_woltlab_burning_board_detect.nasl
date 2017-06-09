###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_woltlab_burning_board_detect.nasl 4316 2016-10-20 15:26:13Z cfi $
#
# WoltLab Burning Board (Lite) Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.800936");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 4316 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-20 17:26:13 +0200 (Thu, 20 Oct 2016) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WoltLab Burning Board (Lite) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of WoltLab Burning
  Board (Lite) and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/wbb", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/upload/index.php", port:port );
  rcvRes2 = http_get_cache( item: dir + "/index.php", port:port );
  rcvRes3 = http_get_cache( item: dir + "/acp/index.php", port:port );

  if( ( rcvRes =~ "HTTP/1.. 200" && "WoltLab Burning Board" >< rcvRes ) ||
      ( rcvRes2 =~ "HTTP/1.. 200" && ( "new WBB.Board." >< rcvRes2 || "<strong>Burning Board" >< rcvRes2 ) ) ||
      ( rcvRes3 =~ "HTTP/1.. 200" && ( ">WoltLab Burning Board" >< rcvRes3 || "new WCF.ACP.Menu" >< rcvRes3 ) ) ) {

    version = "unknown";

    ver = eregmatch( pattern:">Burning Board[&a-z; ]+(Lite )?([0-9.]+([A-Za-z0-9 ]+)?)<", string:rcvRes );
    ver[2] = ereg_replace( pattern:" ", replace:".", string:ver[2] );
    if( ver[2] != NULL ) {
      if( ver[1] == "Lite " ) {
        app_name = "WoltLab Burning Board Lite";
        kb_name = "BurningBoardLite";
        base_cpe = "cpe:/a:woltlab:burning_board_lite";
      } else {
        app_name = "WoltLab Burning Board";
        kb_name = "BurningBoard";
        base_cpe = "cpe:/a:woltlab:burning_board";
      }
      version = ver[2];
    } else {
      ver = eregmatch( pattern:"strong>Burning Board[&a-z; ]+(Lite )?([0-9.]+([A-Za-z0-9 ]+)?)<", string:rcvRes2 );
      ver[2] = ereg_replace( pattern:" ", replace:".", string:ver[2] );
      if( ver[2] != NULL ) {
        if( ver[1] == "Lite " ) {
          app_name = "WoltLab Burning Board Lite";
          kb_name = "BurningBoardLite";
          base_cpe = "cpe:/a:woltlab:burning_board_lite";
        } else {
          app_name = "WoltLab Burning Board";
          kb_name = "BurningBoard";
          base_cpe = "cpe:/a:woltlab:burning_board";
        }
        version = ver[2];
      } else {
        ver = eregmatch( pattern:"Burning Board ([0-9.]+([A-Za-z0-9 ]+)?)", string:rcvRes3 );
        ver[1] = ereg_replace( pattern:" ", replace:".", string:ver[1] );
        if( ver[1] != NULL ) version = ver[1];
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/" + kb_name, value:tmp_version );
    set_kb_item( name:kb_name + "/installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value:version, exp:"^([0-9.]+)\.([0-9a-zA-Z.]+)", base:base_cpe + ":" );
    if( isnull( cpe ) )
      cpe = base_cpe;

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:app_name,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
