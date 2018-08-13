###############################################################################
# OpenVAS Vulnerability Test
# $Id: webfileexplorer_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# WebFileExplorer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100136");
  script_version("$Revision: 10906 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WebFileExplorer Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.webfileexplorer.com/");

  script_tag(name:"summary", value:"This host is running WebFileExplorer, a web based file management
  system.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/fileexplorer", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item:dir + "/", port:port );
  if( isnull( buf ) ) continue;

  if( egrep( pattern:'<title>WebFileExplorer.*</title>', string:buf, icase:TRUE ) &&
      egrep( pattern:'Set-Cookie: fileoptions.*', string:buf, icase:TRUE ) ) {

    vers = "unknown";

    version = eregmatch( string:buf, pattern:'<title>WebFileExplorer v([0-9.]+)</title>', icase:TRUE );
    if( ! isnull( version[1] ) ) vers = chomp( version[1] );

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/webfileexplorer", value:tmp_version );

    cpe = build_cpe( value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:webfileexplorer:web_file_explorer:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:webfileexplorer:web_file_explorer";

    register_product( cpe:cpe, location:install, port:port );
    log_message( data:build_detection_report( app:"WebFileExplorer",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
