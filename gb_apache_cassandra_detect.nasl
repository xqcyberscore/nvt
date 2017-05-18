###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_cassandra_detect.nasl 5888 2017-04-07 09:01:53Z teissa $
#
# Apache Cassandra Detection
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105065");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_version ("$Revision: 5888 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
 script_tag(name:"creation_date", value:"2014-07-18 18:29:45 +0200 (Fri, 18 Jul 2014)");
 script_name("Apache Cassandra Detection");

 tag_summary =
"The script sends a connection request to the server and attempts
to extract the version number from the reply.";


 script_tag(name : "summary" , value : tag_summary);

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(9160);
 exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("cpe.inc");
include("host_details.inc");

port = 9160;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

cmd = 'execute_cql3_query';
cmd_len = strlen( cmd ) % 256 ;

sql = 'select release_version from system.local;';
sql_len = strlen( sql ) % 256 ;

req = raw_string( 0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, cmd_len ) + 
      cmd +
      raw_string( 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01, 0x00,
                  0x00, 0x00, sql_len ) + 
      sql + 
      raw_string( 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00,
                  0x03, 0x00, 0x00, 0x00, 0x01, 0x00 );


alen = strlen( req ) % 256;
req = raw_string( 0x00, 0x00, 0x00, alen ) + req;

send( socket:soc, data:req );
recv = recv( socket:soc, length:4096 );
close( soc );

if( ! recv || "execute_cql3_query" >!< recv ) exit( 0 );

# apache casasandra detected

vers = 'unknown';

for( i = 0; i< strlen( recv ); i++ ) 
{
  if( recv[i] == '\x00' )
    ret += ' ';

 if ( isprint( c:recv[i] ) )  
   ret += recv[i];
}

version = eregmatch( pattern:"release_version\s*([0-9.]+)", string:ret );
if( ! isnull( version[1] ) ) vers = version[1];

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:apache:cassandra:" );
if( ! cpe )
  cpe = 'cpe:/a:apache:cassandra';

register_product( cpe:cpe, location:port + '/tcp', port:port );

log_message( data:build_detection_report( app:"Apache Cassandra",
                                          version:vers,
                                          install:port + '/tcp',
                                          cpe:cpe,
                                          concluded: version[0] ), 
             port:port,
             expert_info:'Request:\n' + hexdump( ddata:req ) + '\nResponse:\n' + hexdump( ddata:recv )  );

exit( 0 );

