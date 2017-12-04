###############################################################################
# OpenVAS Include File
# $Id: smtp_func.inc 7922 2017-11-28 10:06:28Z cfischer $
#
# Support functions for handling SMTP
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 7922 $
#
###############################################################################

function smtp_close( socket ) {

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_close" );

  send( socket:socket, data:'QUIT\r\n' );
  smtp_recv_line( socket:socket );
  close( socket );
}

function smtp_open( port, helo ) {

  local_var soc, data;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_open" );

  soc = open_sock_tcp( port );
  if ( ! soc ) return NULL;

  data = smtp_recv_banner( socket:soc );
  if( ! data ) {
    smtp_close( socket:soc );
    return NULL;
  }

  if( isnull( helo ) ) return soc;

  send( socket:soc, data:strcat( 'HELO ', helo, '\r\n' ) );
  data = smtp_recv_line( socket:soc );
  if( ! ereg( pattern:"^[2-3][0-9][0-9]", string:data ) ) {
    smtp_close( socket:soc );
    return NULL;
  }

  return soc;
}

function smtp_open_ehlo( port, helo ) {

  local_var soc, data;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_open_ehlo" );

  soc = open_sock_tcp( port );
  if ( ! soc ) return NULL;

  data = smtp_recv_banner( socket:soc );
  if( ! data ) {
    smtp_close( socket:soc );
    return NULL;
  }

  if( isnull( helo ) ) return soc;

  send( socket:soc, data:strcat( 'EHLO ', helo, '\r\n' ) );
  data = smtp_recv_line( socket:soc );
  if( ! ereg(pattern:"^[2-3][0-9][0-9]", string:data ) ) {
    smtp_close( socket:soc );
    return NULL;
  }

  return soc;
}

function smtp_send_socket( socket, from, to, body ) {

  local_var socket, from, to, body, buff;

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_send_socket" );
  if( ! from ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#from#-#smtp_send_socket" );
  if( ! to ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#to#-#smtp_send_socket" );
  if( ! body ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#body#-#smtp_send_socket" );

  # display(string("smtp_send_socket from=", from, " to=", to, "\n"));
  # Just to be sure
  send( socket:socket, data:string( "RSET\r\n" ) );
  buff = recv_line( socket:socket, length:2048 );
  # Here, we might test the return code
  if( from !~ ' *<.*> *') from = strcat( '<', from, '>' );
  send( socket:socket, data:string( "MAIL FROM: ", from, "\r\n" ) );
  buff = recv_line( socket:socket, length:2048 );
  if( ! ereg( pattern:"^2[0-9][0-9] ", string:buff ) ) return( 0 );

  if( to !~ ' *<.*> *') to = strcat( '<', to, '>' );
  send( socket:socket, data:string( "RCPT TO: ", to, "\r\n" ) );
  buff = recv_line( socket:socket, length: 2048 );
  if( ! ereg( pattern:"^2[0-9][0-9] ", string:buff ) ) return( 0 );

  send( socket:socket, data:string( "DATA\r\n" ) );
  buff = recv_line( socket:socket, length:2048 );
  if( ! ereg( pattern:"^3[0-9][0-9] ", string:buff ) ) return( 0 );

  # Make sure that every line ends up with \r\n
  # This is not useful yet, as only two scripts send data to the SMTP server
  #body = ereg_replace(string: body, pattern: string("([^\r])\n"), replace: string("\\1\r\n"));
  send( socket:socket, data:body );
  send( socket:socket, data:string( "\r\n.\r\n" ) );
  buff = recv_line( socket:socket, length:2048 );
  if( ! ereg( pattern:"^2[0-9][0-9] ", string:buff ) ) return( 0 );
  return( 1 );
}

function smtp_send_port( port, from, to, body ) {

  local_var s, buff, ret, hostname, port, from, to, body;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_send_port" );
  if( ! from ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#from#-#smtp_send_port" );
  if( ! to ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#to#-#smtp_send_port" );
  if( ! body ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#body#-#smtp_send_port" );

  s = open_sock_tcp( port );
  if( ! s ) return( 0 );

  buff = recv_line( socket:s, length:2048 );
  hostname = get_kb_item( 'smtp/'+ port + '/helo' );
  if( ! hostname ) hostname = 'openvas';
  send( socket:s, data:strcat( 'HELO ', hostname, '\r\n' ) );
  buff = recv_line( socket:s, length:2048 );
  # We should test the code
  ret = smtp_send_socket( socket:s, from:from, to:to, body:body );
  send( socket:s, data:string( "QUIT\r\n" ) );
  close( s );
  return( ret );
}

function smtp_from_header() {

  local_var fromaddr;

  fromaddr = get_kb_item( "SMTP/headers/From" );
  if( ! fromaddr ) fromaddr = "openvas@example.com";
  return( fromaddr );
}

function smtp_to_header() {

  local_var toaddr;

  toaddr = get_kb_item( "SMTP/headers/To" );
  if( ! toaddr ) toaddr = string( "postmaster@[", get_host_ip(), "]" );
  return( toaddr );
}

function get_smtp_banner( port ) {

  local_var sb, banner, soc, port;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_smtp_banner" );

  sb = string( "smtp/banner/", port );
  banner = get_kb_item( sb );
  if( banner ) return( banner );
  if( get_kb_item( "smtp/" + port + "/broken" ) ) return NULL;

  if( ! get_port_state( port ) ) return( 0 );
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_kb_item( name:"smtp/" + port + "/broken", value:TRUE );
    set_kb_item( name: 'SMTP/' + port + '/broken', value:TRUE );
    return NULL;
  }
  banner = smtp_recv_banner( socket:soc );
  close( soc );
  if( ! banner ) {
    set_kb_item( name:"smtp/" + port + "/broken", value:TRUE );
    set_kb_item( name:'SMTP/' + port + '/broken', value:TRUE );
    return NULL;
  }

  replace_kb_item( name:sb, value:banner );
  return( banner );
}


function smtp_recv_line( socket, code, retry, last ) {

  local_var ret, n, r, pat, socket, code, retry, last;

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_recv_line" );

  if( isnull( code ) ) {
   pat = "^[0-9][0-9][0-9]-";
  } else {
   pat = strcat("^", code, "-");
  }

  ret = "";
  r = recv_line( socket:socket, length:4096 );
  #
  n = 0;
  while( ! r && n++ < retry ) {
    r = recv_line( socket:socket, length:4096 );
  }
  #
  n = 0;
  ret = r;
  if( strlen( r ) < 4 ) return r;

  while( ereg( pattern:pat, string:r ) ) {
    n = n + 1;
    r = recv_line( socket:socket, length:4096 );
    if( strlen( r ) == 0 ) break;
    if( n > 512 ) return NULL;
    if( last ) {
      ret = r;
    } else {
      ret = strcat( ret, r );
    }
 }
 return ret;
}

function smtp_recv_banner( socket ) {

  if( ! socket ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_recv_banner" );

  return smtp_recv_line( socket:socket, code:"220" );
}

function get_smtp_port( default ) {

  local_var default, port, p;

  if( ! default ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_smtp_port" );

  port = get_kb_item( "Services/smtp" );
  if( port ) default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( smtp_is_fragile_port( port:default ) ) exit( 0 );

  p = get_kb_item( "SMTP/" + default + "/broken" );
  if( p ) exit( 0 );

  if( ! get_port_state( default ) ) exit( 0 );

  return default;
}

# Duplicated from misc_func.inc
function smtp_is_fragile_port( port ) {

  local_var port, fragile_ports, fragile_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_is_fragile_port" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports ) return;

  foreach fragile_port( fragile_ports ) {
    if( port == fragile_port ) return TRUE;
  }

  return;
}