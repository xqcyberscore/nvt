###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zpanel_detect.nasl 2836 2016-03-11 09:07:07Z benallard $
#
# Zpanel Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105414");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 2836 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:07:07 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2015-10-21 11:00:30 +0200 (Wed, 21 Oct 2015)");
 script_name("Zpanel Detection");

 script_tag(name: "summary" , value: "This script performs HTTP based detection of Zpanel");

 script_tag(name:"qod_type", value:"remote_banner");

 script_summary("Checks for the presence of Zpanel");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

dirs = make_list_unique( "/", "/zpanel", cgi_dirs( port:port ) );

cpe = 'cpe:/a:zpanel:zpanel';

foreach dir ( dirs )
{
  if( dir == "/" ) dir = "";

  url = dir + "/index.php";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );
  if( buf == NULL ) continue;

  if( ( "title>Control Panel - Login</title>" >< buf || "<title>ZPanel" >< buf ) && 
      ( egrep( pattern: "Powered By: .*>ZPanel([ 0-9.]+)?", string: buf, icase: TRUE ) ||
        "This server is running: ZPanel" >< buf ) )
  {
    if( strlen( dir ) > 0 )
      install = dir;
    else
    {
      install = "/";
      root_install = TRUE;
    }

    vers = "unknown";
    ### try to get version 
    version = eregmatch( string: buf, pattern: "(: |>)ZPanel ([0-9.]+)</(a|p)>",icase:TRUE );

    if ( ! isnull( version[2] ) )
    {
      vers = chomp( version[2] );
      cpe += ':' + vers;
    }

    set_kb_item(name:"zpanel/installed",value:TRUE);

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Zpanel",
                                               version:vers,
                                               install:install,
                                               cpe:cpe,
                                               concluded: version[0] ),
                 port:port );

  if( root_install ) exit( 0 );

  }
}

exit(0);

