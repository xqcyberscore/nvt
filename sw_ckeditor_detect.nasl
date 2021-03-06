###############################################################################
# OpenVAS Vulnerability Test
#
# CKEditor Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111094");
  script_version("2019-09-16T06:54:58+0000");
  script_tag(name:"last_modification", value:"2019-09-16 06:54:58 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2016-04-17 18:00:00 +0200 (Sun, 17 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CKEditor Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request
  to the server and attempts to detect the application and its version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:80 );

cgidirs = make_list_unique( "/", cgi_dirs( port:port ) );
subdirs = make_list( "/", "/ckeditor", "/editor",
                     "/admin/ckeditor",
                     "/sites/all/modules/ckeditor",
                     "/resources/ckeditor",
                     "/clientscript/ckeditor",
                     "/wp-content/plugins/ckeditor-for-wordpress/ckeditor" );
foreach cgidir( cgidirs ) {
  foreach subdir( subdirs ) {
    # To avoid doubled calls and calls like //dir
    if( cgidir != "/" && subdir == "/" ) subdir = "";
    if( cgidir == "/" ) cgidir = "";
    dirs = make_list_unique( dirs, cgidir + subdir );
  }
}

foreach dir( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item: dir + "/ckeditor.js", port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  req2 = http_get( item: dir + "/CHANGES.md", port:port );
  buf2 = http_keepalive_send_recv( port:port, data:req2 );

  if( ( "CKSource" >< buf && "CKEDITOR" >< buf ) ||
      buf2 =~ "CKEditor . Changelog" ) {

    version = 'unknown';

    ver = eregmatch( pattern:'version:"([0-9.]+)"', string:buf, icase:TRUE );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      ver = eregmatch( pattern:"## CKEditor ([0-9.]+)", string:buf2 );
      if( ! isnull( ver[1] ) ) version = ver[1];
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ckeditor:ckeditor:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ckeditor:ckeditor';

    set_kb_item( name:"www/" + port + "/ckeditor", value:version );
    set_kb_item( name:"ckeditor/installed", value:TRUE );

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"CKEditor",
                                              version:version,
                                              concluded:ver[0],
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );
