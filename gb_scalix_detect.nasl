###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scalix_detect.nasl 13138 2019-01-18 07:48:30Z cfischer $
#
# Scalix Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105102");
  script_version("$Revision: 13138 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 08:48:30 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2014-11-03 13:25:47 +0100 (Mon, 03 Nov 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Scalix Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl", "http_version.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/www", 80, "Services/smtp", 25, 465, 587, "Services/imap", 143);

  script_tag(name:"summary", value:"The script sends a connection request to the server and
  attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");
include("imap_func.inc");

function _report( port, version, location, concluded, service )
{
  if( ! version || version == '' ) return;

  if( ! location ) location = port + '/tcp';

  set_kb_item( name:'scalix/' + port + '/version', value:version );
  set_kb_item( name:"scalix/installed",value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:scalix:scalix:" );
  if( ! cpe )
    cpe = "cpe:/a:scalix:scalix";

  register_product( cpe:cpe, location:location, port:port, service:service );

  log_message( data: build_detection_report( app:"Scalix",
                                             version:version,
                                             install:location,
                                             cpe:cpe,
                                             concluded: concluded ),
               port:port );


  exit( 0 );

}

ports = get_kb_list( "Services/www" );
if( ! ports )
  ports = make_list( 80 );

foreach port ( ports )
{
  if( get_port_state( port ) )
  {
    url = "/webmail/";
    buf = http_get_cache( item:url, port:port );

    if( buf && "<title>Login to Scalix Web Access" >< buf )
    {
      vers = 'unknown';
      buf_sp = split( buf, keep:FALSE );

      for( i=0; i< max_index( buf_sp ); i++ )
      {
        if( "color:#666666;font-size:9px" >< buf_sp[ i ] )
        {
          if( version = eregmatch( pattern:"([0-9.]+)" , string:buf_sp[ i + 1 ] ) )
          {
            _report( port:port, version:version[1], location:"/webmail/", concluded:version[0], service:"www" );
            break;
          }
        }
      }
    }
  }
}

ports = smtp_get_ports();
foreach port ( ports )
{
  banner = get_smtp_banner( port:port );
  if( banner && "ESMTP Scalix SMTP" >< banner )
  {
    if( version = eregmatch( pattern:"ESMTP Scalix SMTP Relay ([0-9.]+);" , string:banner ) )
    {
      _report( port:port, version:version[1], concluded:'SMTP banner', service:"smtp" );
    }
  }
}

ports = get_kb_list( "Services/imap" );
if( ! ports )
  ports = make_list( 143 );

foreach port ( ports )
{
  if( get_port_state( port ) )
  {
    banner = get_imap_banner( port:port );
    if( banner && "Scalix IMAP server" >< banner )
    {
      if( version = eregmatch( pattern:"Scalix IMAP server ([0-9.]+)" , string:banner ) )
      {
        _report( port:port, version:version[1], concluded:'IMAP banner', service:"imap" );
      }
    }
  }
}

exit( 0 );