###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_detect.nasl 5896 2017-04-07 14:47:18Z cfi $
#
# ownCloud Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103564");
  script_version("$Revision: 5896 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-07 16:47:18 +0200 (Fri, 07 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-09-12 14:18:24 +0200 (Wed, 12 Sep 2012)");
  script_name("ownCloud Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gb_nextcloud_detect.nasl"); # Nextcloud needs to be detected before
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of ownCloud.

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

foreach dir( make_list_unique( "/", "/oc", "/owncloud", "/ownCloud", "/OwnCloud", "/cloud", cgi_dirs( port:port ) ) ) {

  if( get_kb_item( "nextcloud/install/" + port + "/" + dir ) ) continue; # From gb_nextcloud_detect.nasl to avoid double detection of Nc and oC

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/status.php";
  buf = http_get_cache( item:url, port:port );

  # nb: Don't check for 200 as a 400 will be returned when accessing to an untrusted domain
  if( "egroupware" >!< tolower( buf ) && # EGroupware is using the very same status.php
    ( egrep( string:buf, pattern:'"installed":("true"|true),("maintenance":(true|false),)?("needsDbUpgrade":(true|false),)?"version":"([0-9.a]+)","versionstring":"([0-9.a]+)","edition":"(.*)"' ) ||
      ( "You are accessing the server from an untrusted domain" >< buf && ">ownCloud<" >< buf ))) {

    version = "unknown";
    extra = NULL;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    #Basic auth check for default_http_auth_credentials.nasl
    foreach authurl( make_list( dir + "/remote.php/dav", dir + "/remote.php/webdav" ) ) {

      req = http_get( item:authurl, port:port );
      buf2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf2 =~ "HTTP/1.. 401" ) {
        replace_kb_item( name:"www/content/auth_required", value:TRUE );
        set_kb_item( name:"www/" + port + "/content/auth_required", value:authurl );
        break;
      }
    }

    ver = eregmatch( string:buf, pattern:'version":"([0-9.a]+)","versionstring":"([0-9.a]+)"', icase:TRUE );
    if( ! isnull( ver[2] ) ) version = ver[2];

    replace_kb_item( name:"owncloud_or_nextcloud/installed", value:TRUE );
    replace_kb_item( name:"owncloud/installed", value:TRUE );

    if( "You are accessing the server from an untrusted domain" >< buf ) {
      extra = "ownCloud is blocking full access to this server because the scanner is accessing the server from an untrusted domain.";
      extra += " To fix this configure the scanner to access the server on the expected domain.";
    }

    cpe = build_cpe( value:version, exp:"^([0-9.a]+)", base:"cpe:/a:owncloud:owncloud:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:owncloud:owncloud';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"ownCloud",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
