###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opc_ua_detect.nasl 10317 2018-06-25 14:09:46Z cfischer $
#
# OPC-UA Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140050");
  script_version("$Revision: 10317 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 16:09:46 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2016-11-03 14:59:49 +0100 (Thu, 03 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OPC-UA Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 4840);

  script_tag(name:"summary", value:"This script performs detection of OPC-UA Servers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

port = get_unknown_port( default:4840 );
host = get_host_name();

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );

opc_req_header = raw_string('HEL', # Message Type (Hello)
                            'F'    # Chunk Type
                           );

EndPointUrl = 'opc.tcp://' + host + ':' + port;

epu_len = strlen( EndPointUrl );
epu_len = mkdword( epu_len );

opc_req_footer = raw_string( 0x00,0x00,0x00,0x00,                         # Version (0)
                             0x00,0x00,0x01,0x00,                         # ReceiveBufferSeize (65536)
                             0x00,0x00,0x01,0x00,                         # SendBufferSize (65536)
                             0x00,0x00,0x00,0x00,                         # MaxMessageSize (0)
                             0x00,0x00,0x00,0x00,                         # MaxChunkCount (0)
                             epu_len,                                     # EndPointUrlLen
                             EndPointUrl                                  # EndPointUrl
                           );

l = ( strlen( opc_req_header ) + strlen( opc_req_footer ) + 4 );

len = mkdword( l );

opc_req = opc_req_header + len + opc_req_footer;

send( socket:soc, data:opc_req );
recv = recv( socket:soc, length:4 );
close( soc );

if( strlen( recv ) != 4 || ( recv !~ '^ACKF' && recv !~ '^ERRF' ) ) exit( 0 );

register_service( port:port, proto:'opc-ua' );
log_message( port:port, data:"A OPC-UA Server seems to be running at this port." );

exit( 0 );
