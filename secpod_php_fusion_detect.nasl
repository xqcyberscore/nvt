###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_fusion_detect.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# Detection of PHP-Fusion Version
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900612");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2009-04-07 09:44:25 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Detection of PHP-Fusion Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.php-fusion.co.uk");

  script_tag(name:"summary", value:"Detection of PHP-Fusion.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

## set th kb and CPE
function _SetCpe( version, tmp_version, dir ) {

  ## set the kb
  set_kb_item( name:"www/" + port + "/php-fusion", value: tmp_version );
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:php-fusion:php-fusion:" );

  if( isnull( cpe ) )
    cpe = "cpe:/a:php-fusion:php-fusion";

  ## set the CPE
  register_product( cpe:cpe, location:dir, port:port );
  log_message( data:build_detection_report( app:"PHP-Fusion",
                                            version:version,
                                            install:dir,
                                            cpe:cpe,
                                            concluded:version ),
                                            port:port );
}

foreach dir( make_list_unique( "/", "/php-fusion", "/phpfusion", cgi_dirs( port:port ) ) ) {

  flag = 0;
  tmp_version= "";
  version= "";

  install = dir;
  if( dir == "/" ) dir = "";

  foreach subdir( make_list( "/", "/files", "/php-files" ) ) {

    sndReq = http_get( item:dir + subdir + "/news.php", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if( rcvRes =~ "HTTP/1.. 200 OK" && ( "PHP-Fusion Powered" >< rcvRes ||
        ">Powered by <a href='https://www.php-fusion.co.uk'>PHP-Fusion</a>" >< rcvRes ) ) {

      set_kb_item( name:"php-fusion/installed", value:TRUE );
      flag = 1;

      ## Match the version from response
      matchline = egrep( pattern:"></a> v[0-9.]+", string:rcvRes );
      matchVersion = eregmatch( pattern:"> v([0-9.]+)", string:matchline );
      if( matchVersion[1] != NULL ) {
        version = matchVersion[1];
        tmp_version = matchVersion[1] + " under " + install;
      }
      if( version ) {
        _SetCpe( version:version, tmp_version:tmp_version, dir:install );
      }
    }
  }

  ## If PHP-Fusion is installed and not get the version from news.php
  ## check for the version in readme-en.html
  if( ! version ) {

    sndReq = http_get( item:dir + "/readme-en.html", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    ## Confirm its PHP-Fusion Readme only
    if( rcvRes =~ "HTTP/1.. 200 OK" && "PHP-Fusion Readme" >< rcvRes ) {

      set_kb_item( name:"php-fusion/installed", value:TRUE );
      flag = 1;

      ## Match the version
      matchline = egrep( pattern:"Version:</[a-z]+> [0-9.]+", string:rcvRes );
      matchVersion = eregmatch( pattern:"> ([0-9.]+)", string:matchline );

      if( matchVersion[1] != NULL ) {
        version = matchVersion[1];
        tmp_version = matchVersion[1] + " under " + install;
      }

      ## set the cpe and version
      if( version ) {
        _SetCpe( version:version, tmp_version:tmp_version, dir:install );
      }
    }
  }

  ## If PHP-Fusion is installed and not able get the version from any
  ## of the file set the version as "unknown" and CPE
  if( ! version && flag ) {
    version = "Unknown";
    tmp_version = version + " under " + install;
    _SetCpe( version:version, tmp_version:tmp_version, dir:install );
  }
}

exit( 0 );