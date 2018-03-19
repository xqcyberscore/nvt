##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zikula_detect.nasl 9126 2018-03-17 16:19:49Z cfischer $
#
# Detection of zikula or Post-Nuke Version
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-12
#  - Modified the script to detect the recent versions
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900620");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9126 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-17 17:19:49 +0100 (Sat, 17 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-06-02 12:54:52 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Detecting the zikula or PostNuke version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the version of the PostNuke installed
  on remote system and sets the equivalent value in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}



# The PostNuke product is stopped and again started same  product with the name zikula.
# This script first searches the version of postnuke installed , if it not founds then
# it serches for the zikula installed.

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/postnuke", "/PostNuke", "/zikula", "/framework", "/Zikula_Core", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  # searching for postnuke version in different possible files
  if( 'PostNuke' >< rcvRes && egrep( pattern:"<meta name=.generator. content=.PostNuke", string:rcvRes, icase:TRUE ) ) {

    version = "unknown";

    ver_str = egrep(pattern:"<meta name=.generator. content=.PostNuke", string:rcvRes, icase:TRUE );
    ver_str = chomp( ver_str );
    ver = ereg_replace( pattern:".*content=.PostNuke ([0-9].*) .*", string:ver_str, replace:"\1" );
    if( ver == ver_str ) {
      sndReq = http_get( item: dir + "/docs/manual.txt", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

      if( 'PostNuke' >< rcvRes && egrep( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*$", string:rcvRes ) ) {
        ver_str = egrep( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*$", string:rcvRes );
        ver_str = chomp( ver_str );
        ver = ereg_replace( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*\(([0-9].*)\)", string:ver_str, replace:"\2" );
        # if postnuke is installed sets the kb values and exits
        if( ver ) version = ver;
      }
    }

    set_kb_item( name:"postnuke/detected", value:TRUE );
    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/postnuke", value:tmp_version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:postnuke:postnuke:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:postnuke:postnuke';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"PostNuke",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                                              port:port );
    exit( 0 );
  }

  # searching for postnuke version in different possible files
  if( "postnuke" >< dir || "PostNuke" >< dir ) {

    sndReq = http_get( item: dir + "/themes/SeaBreeze/style/style.css", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if( rcvRes =~ "HTTP/1.. 200" ) {

      postNuke = egrep( pattern:"PN [0-9.]+", string:rcvRes );
      ver = eregmatch( pattern:"([0-9.]+)", string:postNuke );
      if( ver[0] != NULL ) {

        set_kb_item( name:"postnuke/detected", value:TRUE );
        tmp_version = ver[0] + " under " + install;
        set_kb_item( name:"www/"+ port + "/postnuke", value:tmp_version );

        cpe = build_cpe( value:ver[0], exp:"^([0-9.]+)", base:"cpe:/a:postnuke:postnuke:" );
        if( isnull( cpe ) )
          cpe = 'cpe:/a:postnuke:postnuke';

        register_product( cpe:cpe, location:install, port:port );

        log_message( data:build_detection_report( app:"PostNuke",
                                                  version:ver[0],
                                                  install:install,
                                                  cpe:cpe,
                                                  concluded:ver[0] ),
                                                  port:port );

        exit( 0 );
      }
    }
  }

  # searching for the zikula version in zikula directory
  sndReq = http_get( item: dir + "/docs/distribution/tour_page1.htm", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  rcvRes2 = http_get_cache( item: dir + "/index.php", port:port );
  rcvRes3 = http_get_cache( item: dir + "/", port:port );

  if( ( rcvRes =~ "HTTP/1.. 200" && "congratulations and welcome to Zikula" >< rcvRes ) ||
      ( rcvRes2 =~ "HTTP/1.. 200" && egrep( pattern:"Powered by .*Zikula", string:rcvRes2 ) ) ||
      ( rcvRes3 =~ "HTTP/1.. 200" && egrep( pattern:"Powered by .*Zikula", string:rcvRes3 ) ) ) {

    version = "unknown";

    zikula = egrep( pattern:"welcome to Zikula [0-9.]+", string:rcvRes );
    ver = eregmatch( pattern:"([0-9.]+)", string:zikula );
    if( ver[0] != NULL ) {
      version = ver[0];
    } else {
      sndReq = http_get( item: dir + "/docs/CHANGELOG", port:port );
      rcvRes = http_keepalive_send_recv( port:port, data:sndReq );
      zikula = egrep( pattern:"ZIKULA [0-9.]+", string:rcvRes );
      ver = eregmatch( pattern:"([0-9.]+)", string:zikula );
      if( ver[0] != NULL ) version = ver[0];
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/zikula", value:tmp_version );
    set_kb_item( name:"zikula/installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zikula:zikula_application_framework:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:zikula:zikula_application_framework';

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Zikula",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );