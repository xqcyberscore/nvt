###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redis_detect.nasl 6065 2017-05-04 09:03:08Z teissa $
#
# Redis Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103844");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_version ("$Revision: 6065 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-04 11:03:08 +0200 (Thu, 04 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-02 13:58:18 +0100 (Mon, 02 Dec 2013)");
  script_name("Redis Detection");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name : "summary" , value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/unknown", 6379);

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

cpe = 'cpe:/a:redis:redis';

port = get_unknown_port( default:6379 );

soc = open_sock_tcp(port);
if(!soc)exit(0);

send( socket:soc, data:'PING\r\n');
recv = recv( socket:soc, length:32 );

if( "-NOAUTH" >< recv )
{
  # try default pass
  send( socket:soc, data:'AUTH foobared\r\n' );
  recv = recv( socket:soc, length:32 );
  if( "-ERR invalid password" >< recv )
  {
    close( soc );
    exit( 0 );
  }
  set_kb_item( name:"redis/" + port + "/default_password", value:TRUE );
}
else if( "PONG" >< recv )
{
  send( socket:soc, data:'AUTH openvas\r\n' );
  recv = recv( socket:soc, length:64 );
  if( "-ERR Client sent AUTH, but no password is set" >< recv )
    set_kb_item( name:"redis/" + port + "/no_password", value:TRUE );
}

send( socket:soc, data:'info\r\n' );
recv = recv( socket:soc, length:1024 );
close( soc );

if( "redis_version" >!< recv ) exit( 0 );

set_kb_item( name:"redis/installed", value:TRUE );

rv = 'unknown';

redis_version = eregmatch( pattern:'redis_version:([^\r\n]+)', string:recv );
if( ! isnull( redis_version[1] ) )
{
  set_kb_item( name:'redis/' + port + '/version', value:redis_version[1] );
  rv = redis_version[1];
  cpe += ':' + rv;
}

register_service( port: port, proto: 'redis' );
register_product( cpe:cpe, location:port + "/tcp", port:port );

log_message( data: build_detection_report( app:"Redis",
                                           version:rv,
                                           install:port + "/tcp",
                                           cpe:cpe,
                                           concluded: redis_version[0] ),
             port:port );

exit(0);

