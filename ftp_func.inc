###############################################################################
# OpenVAS Include File
# $Id: ftp_func.inc 7922 2017-11-28 10:06:28Z cfischer $
#
# Methods for handling FTP
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi <arboi@alussinan.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 7922 $
#
###############################################################################

global_var _ftp_func_debug;
_ftp_func_debug = FALSE;

function ftp_close( socket ) {

  local_var socket;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_close" );
    return;
  }

  send( socket:socket, data:'QUIT\r\n' );
  close( socket );
}

function get_ftp_banner( port ) {

  local_var banner, soc, port, cmd, csid_banner, user, pass;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_ftp_banner" );
    return;
  }

  banner = get_kb_item( "ftp/banner/" + port );
  if( banner ) return( banner );
  if( get_kb_item( "ftp/" + port + "/broken" ) ) exit( 0 );

  if( ! get_port_state( port ) ) return;
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
    return;
  }
  banner = ftp_recv_line( socket:soc, retry:1 );
  ftp_close( socket:soc );
  if( ! banner ) {
    set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
    return;
  }

  # Client / Server Identification (CSID)
  # https://tools.ietf.org/html/draft-peterson-streamlined-ftp-command-extensions-10#section-6
  # Some servers like Serv-U implement this and report the Server-Type and Version even if the Banner is changed to something generic
  # Example Client Request: CSID Name=FTP Voyager; Version=15.0.0.2;
  # Example Server Response: 200 Name=Serv-U; Version=7.0.0.5; OS=Windows XP; OSVer=5.1.2600; CaseSensitive=0; DirSep=/;
  # Example Server Reponse when not logged in: 530 Not logged in.
  cmd = "CSID Name=OpenVAS; Version=" + OPENVAS_VERSION + ";";
  csid_banner = get_ftp_cmd_banner( port:port, cmd:cmd );
  if( egrep( pattern:"^200 .*", string:csid_banner ) ) {
    banner += csid_banner;
  } else if( egrep( pattern:"^530 .*", string:csid_banner ) ) {

    user = get_kb_item( "ftp/login" );
    pass = get_kb_item( "ftp/password" );

    if( user && pass ) {
      soc = open_sock_tcp( port );
      if( soc ) {
        if( ftp_authenticate( socket:soc, user:user, pass:pass ) ) {
          csid_banner = ftp_send_cmd( socket:soc, cmd:cmd );
          if( egrep( pattern:"^200 .*", string:csid_banner ) ) {
            banner += csid_banner;
            replace_kb_item( name:"ftp/" + cmd + "_banner/" + port, value:csid_banner );
          }
        }
        ftp_close( socket:soc );
      }
    }
  }

  replace_kb_item( name:"ftp/banner/" + port, value:banner );
  return banner;
}

function get_ftp_cmd_banner( port, cmd ) {

  local_var banner, soc, port, cmd;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_ftp_cmd_banner" );
    return;
  }

  if( ! cmd ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#get_ftp_cmd_banner" );
    return;
  }

  banner = get_kb_item( "ftp/" + cmd + "_banner/" + port );
  if( banner ) return banner;
  if( get_kb_item( "ftp/" + port + "/broken" ) ) exit( 0 );

  if( ! get_port_state( port ) ) return;
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_kb_item( name:"ftp/" + port + "/broken", value:TRUE );
    return;
  }
  ftp_recv_line( socket:soc );
  banner = ftp_send_cmd( socket:soc, cmd:cmd );
  ftp_close( socket:soc );
  if( ! banner ) {
    return;
  }
  replace_kb_item( name:"ftp/" + cmd + "_banner/" + port, value:banner );
  return banner;
}

function ftp_send_cmd( socket, cmd ) {

  local_var socket, cmd;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_send_cmd" );
    return;
  }

  if( ! cmd ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cmd#-#ftp_send_cmd" );
    return;
  }

  send( socket:socket, data:cmd + '\r\n' );
  return ftp_recv_line( socket:socket );
}

function ftp_recv_line( socket, retry ) {

  local_var n, r, res, t1, t2, socket, retry;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_recv_line" );
    return;
  }

  r = recv_line( socket:socket, length:65535 );
  n = 0;
  if( _ftp_func_debug ) t1 = unixtime();
  while( strlen( r ) == 0 && n ++ < retry )
    r = recv_line( socket:socket, length:65535 );
    if( _ftp_func_debug ) {
      t2 = unixtime();
      if( n > 0 && t2 - t1 > 1 ) display( 'ftp_recv_line: retried ', n, ' time( s ) = ', t2-t1, 's. Increase read timeout!\n' );
    }
    if( strlen( r ) < 4 )
      return r;

  n = 0;
  res = r;
  # Some FTP servers have a broken banner on several lines with a leading space
  while( ( strlen( r ) > 3 && r[3] == "-" ) || ( strlen( r ) >= 3 && r[0] == ' ' ) ) {
    n ++;
    r = recv_line( socket:socket, length:65535 );
    if( n > 255 )
      return;
    res += r;
  }
  return res;
}

function ftp_recv_listing( socket ) {

  local_var n, r, buf, socket;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_recv_listing" );
    return;
  }

  n = 0;
  r = recv_line( socket:socket, length:65535 );
  buf = r;
  while( strlen( r ) ) {
    n ++;
    if( n > 4096 )
      return;
    r = recv_line( socket:socket, length:65535 );
    buf += r;
  }
  return buf;
}

function ftp_recv_data( socket, line ) {

  local_var buf, bytes, min, socket, line;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_recv_data" );
    return;
  }

  if( line != NULL ) {
    bytes = ereg_replace( pattern:"^150.*\(([0-9]*) .*\)", string:line, replace:"\1" );
  }

  if( ! bytes ) {
    bytes = 8192;
    min = 1;
  } else {
    min = int( bytes );
    bytes = int( bytes);
  }

  return recv( socket:socket, min:bytes, length:bytes );
}

#
# Logs into the remote FTP server
#
function ftp_authenticate( socket, user, pass ) {

  local_var r, socket, user, pass;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_authenticate" );
    return;
  }

  if( ! user ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#user#-#ftp_authenticate" );
  if( ! pass ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pass#-#ftp_authenticate" );

  r = ftp_recv_line( socket:socket ); # Receive the banner
  send( socket:socket, data:'USER ' + user + '\r\n' );
  r = ftp_recv_line( socket:socket );
  if( r[0] != '3' && r[0] != '2' ) return FALSE;

  send( socket:socket, data:'PASS ' + pass + '\r\n' );
  r = ftp_recv_line( socket:socket );
  if( r[0] != '2' ) {
    return FALSE;
  } else {
    return TRUE;
  }
}

#
# Returns the port opened on the remote side through a 'PASV' command
#
function ftp_pasv( socket ) {

  local_var r, port, array, socket;

  if( ! socket ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#ftp_pasv" );
    return;
  }

  send( socket:socket, data:'PASV\r\n' );
  r = ftp_recv_line( socket:socket );
  if( r[0] != '2' ) return FALSE;
  port = egrep( pattern:"^227 .* \([0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+\)", string:r );
  if( ! port ) return FALSE;
  array = eregmatch( pattern:"^227 .* \([0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9]+),([0-9]+)\)", string:port );
  if( isnull( array ) ) return FALSE;
  port = int( array[1] ) * 256 + int( array[2] );
  return port;
}

function get_ftp_port( default ) {

  local_var default, port, p;

  if( ! default ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_ftp_port" );

  port = get_kb_item( "Services/ftp" );
  if( port ) default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( ftp_is_fragile_port( port:default ) ) exit( 0 );

  p = get_kb_item( "ftp/" + default + "/broken" );
  if( p ) exit( 0 );

  if( ! get_port_state( default ) ) exit( 0 );

  return default;
}

# Duplicated from misc_func.inc
function ftp_is_fragile_port( port ) {

  local_var port, fragile_ports, fragile_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#ftp_is_fragile_port" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports ) return;

  foreach fragile_port( fragile_ports ) {
    if( port == fragile_port ) return TRUE;
  }

  return;
}
