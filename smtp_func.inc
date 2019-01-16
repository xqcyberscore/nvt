###############################################################################
# OpenVAS Include File
# $Id: smtp_func.inc 13096 2019-01-16 11:03:54Z cfischer $
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
# $Revision: 13096 $
#
###############################################################################

# Global vars to avoid that we're repeatedly asking redis for something we already know.
global_var _smtp_is_broken_array, _smtp_is_wrapped_array, __smtp_helo;

# nb: key is the port or NULL (if not previously checked), value TRUE/FALSE if broken/wrapped or not
_smtp_is_broken_array = make_array();
_smtp_is_wrapped_array = make_array();

# @brief Closes a passed TCP socket of a SMTP server by first sending a QUIT message to the service.
#
# @param socket     The socket to close.
# @param check_data The (mandatory) data which was previously received by other functions. Based on this
#                   data (e.g. if it contains a 3 ASCII Digits code or FALSE of @ref smtp_recv_line) the
#                   function decides if the final QUIT command should be sent.
#
# @return NULL
#
function smtp_close( socket, check_data ) {

  local_var socket, check_data;

  if( ! socket ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_close" );
    return;
  }

  if( check_data =~ "^[0-9]{3}[ -]" || check_data == FALSE ) {
    send( socket:socket, data:'QUIT\r\n' );
    smtp_recv_line( socket:socket );
  }
  close( socket );
}

# @brief Opens a connection to a SMTP server and returns the opened socket.
#
# @param port The port of the remote SMTP server.
# @param helo An (optional) string which is sent within an HELO request to the server. If no
#             string is passed an opened socket will be returned directly. If the string is
#             passed the function will verify if the server has replied with an SMTP status
#             code in the range of 2-3xx.
#
# @return The opened socket or NULL if no connection could be openend, no data was
#         received or no port parameter wasn passed.
#
function smtp_open( port, helo ) {

  local_var port, helo;
  local_var soc, data;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_open" );
    return NULL;
  }

  soc = open_sock_tcp( port );
  if ( ! soc )
    return NULL;

  data = smtp_recv_banner( socket:soc );
  if( ! data ) {
    smtp_close( socket:soc, check_data:data );
    return NULL;
  }

  if( isnull( helo ) )
    return soc;

  send( socket:soc, data:strcat( 'HELO ', helo, '\r\n' ) );
  data = smtp_recv_line( socket:soc, code:"[2-3][0-9]{2}" );
  if( ! data ) {
    smtp_close( socket:soc, check_data:data );
    return NULL;
  }

  return soc;
}

# @brief Opens a connection to a SMTP server and returns the opened socket.
#
# @param port The port of the remote SMTP server.
# @param helo An (optional) string which is sent within an EHLO request to the server. If no
#             string is passed an opened socket will be returned directly. If the string is
#             passed the function will verify if the server has replied with an SMTP status
#             code in the range of 2-3xx.
#
# @return The opened socket or NULL if no connection could be openend, no data was
#         received or no port parameter wasn passed.
#
function smtp_open_ehlo( port, helo ) {

  local_var port, helo;
  local_var soc, data;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_open_ehlo" );
    return NULL;
  }

  soc = open_sock_tcp( port );
  if ( ! soc )
    return NULL;

  data = smtp_recv_banner( socket:soc );
  if( ! data ) {
    smtp_close( socket:soc, check_data:data );
    return NULL;
  }

  if( isnull( helo ) )
    return soc;

  send( socket:soc, data:strcat( 'EHLO ', helo, '\r\n' ) );
  data = smtp_recv_line( socket:soc, code:"[2-3][0-9]{2}" );
  if( ! data ) {
    smtp_close( socket:soc, check_data:data );
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

# @brief Sends an e-mail to a SMTP server.
#
# @param The port of the SMTP server.
# @param The "from" field used in the e-mail.
# @param The "to" field used in the e-mail.
# @param The body to send in the e-mail.
#
# @return The received response of the SMTP server or NULL if it was not possible
#         to open a connection, not all required parameters where passed, the remote
#         SMTP server doesn't accept us or is no SMTP server at all.
#
function smtp_send_port( port, from, to, body ) {

  local_var port, from, to, body;
  local_var socket, ret;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#smtp_send_port" );
    return NULL;
  }

  if( ! from ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#from#-#smtp_send_port" );
    return NULL;
  }

  if( ! to ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#to#-#smtp_send_port" );
    return NULL;
  }

  if( ! body ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#body#-#smtp_send_port" );
    return NULL;
  }

  socket = smtp_open( port:port, helo:get_smtp_helo_from_kb( port:port ) );
  if( ! socket )
    return NULL;

  ret = smtp_send_socket( socket:socket, from:from, to:to, body:body );
  smtp_close( socket:socket, check_data:ret );
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

# @brief Sends a request to a SMTP server and receives the returned banner. If a banner was received it
#        is saved into the knowledge base. If a banner for a port was requested which was requested
#        previously the cached banner will be returned instead of doing a new request.
#
# @param port The port of the remote SMTP server.
#
# @return The banner of the remote host, NULL if no response was received or the remote port wasn't scanned
#         and FALSE if no port parameter was passed.
#
function get_smtp_banner( port ) {

  local_var port;
  local_var sb, banner, soc;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_smtp_banner" );
    return FALSE;
  }

  sb = string( "smtp/banner/", port );
  banner = get_kb_item( sb );
  if( banner )
    return( banner );

  # TBD: Also check for get_smtp_is_marked_wrapped?
  if( get_smtp_is_marked_broken( port:port ) )
    return NULL;

  if( ! get_port_state( port ) )
    return NULL;

  # nb: Don't use smtp_open() as we want to grab the banner below.
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_smtp_is_marked_broken( port:port );
    return NULL;
  }

  banner = smtp_recv_banner( socket:soc, retry:1 );
  smtp_close( socket:soc, check_data:banner );

  if( ! banner ) {
    set_smtp_is_marked_broken( port:port );
    return NULL;
  }

  replace_kb_item( name:sb, value:banner );
  return( banner );
}

# @brief Receives data from a SMTP server over the given socket. The function will verify if
#        the received data is related to SMTP responses.
#
# @param socket The socket to the SMTP server.
# @param code   An (optional) string or regex which is used to verify the received data against.
#               If this parameter isn't passed the default regex of ^[0-9]{3}[ -] is assumed.
#               If e.g. a code of 220 is passed the following regex is used: ^220[ -].
# @param retry  An (optional) amout of retries which should be used for the initial connection
#               if no data was received. If this parameter isn't passed no retry will be done.
# @param last   An (optional) parameter to specify (via a passed TRUE/FALSE) if only the last
#               data matching the mentioned regex in the 'code' parameter should be returned.
#               If this parameter isn't passed all data received is returned.
#
# @return The received data or NULL if the received data is not matching against the regex, no
#         data was received at all or no socket parameter was passed.
#
function smtp_recv_line( socket, code, retry, last ) {

  local_var socket, code, retry, last;
  local_var pat, r, n, ret;

  if( ! socket ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_recv_line" );
    return NULL;
  }

  if( isnull( retry ) )
    retry = 0;

  if( isnull( last ) )
    last = FALSE;

  if( isnull( code ) )
    pat = "^[0-9]{3}[ -]";
  else
    pat = strcat("^", code, "[ -]");

  r = recv_line( socket:socket, length:4096 );

  n = 0;
  while( ! r && n++ < retry ) {
    r = recv_line( socket:socket, length:4096 );
  }

  n = 0;
  ret = r;
  if( strlen( r ) < 4 || r !~ "^[0-9]{3}[ -]" )
    return NULL;

  # nb: We want to differ between NULL and FALSE in the return values here.
  if( ! ereg( pattern:pat, string:r ) )
    return FALSE;

  while( ereg( pattern:pat, string:r ) ) {
    n++;
    r = recv_line( socket:socket, length:4096 );
    if( strlen( r ) == 0 )
      break;

    if( n > 512 )
      return FALSE;

    if( last )
      ret = r;
    else
      ret = strcat( ret, r );
  }
  return ret;
}

# @brief Receives the initial banner of a SMTP server over the given socket. The function will verify if
#        the received data is related to SMTP responses and is matching a 220 return code.
#
# @param socket The socket to the SMTP server.
# @param retry  An (optional) amout of retries which should be used for the initial connection
#               if no data was received. If this parameter isn't passed no retry will be done.
#
# @return The received data or NULL if the received data is not matching a 220 return code, no
#         data was received at all or no socket parameter was passed.
#
function smtp_recv_banner( socket, retry ) {

  local_var socket, retry;

  if( ! socket ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#smtp_recv_banner" );
    return NULL;
  }

  return smtp_recv_line( socket:socket, retry:retry, code:"220" );
}

# @brief Returns all SMTP ports of the target system which are saved
#        in the KB entry "Services/smtp" found by the scanner. If no
#        ports where found open or no "default" parameter is passed
#        (if "nodefault" isn't set to TRUE) it will exit. In the case
#        where the "unscanned_closed" scanner setting is set to "no"
#        it will return the port passed via the default parameter.
#
# @param default   The port to return if "unscanned_closed" is set to "no" and no ports have been found open.
# @param nodefault Don't exit if no "default" parameter is passed, it still will return if no SMTP servers are detected at all.

function get_smtp_port( default, nodefault ) {

  local_var default, nodefault, port;

  if( ! default && ! nodefault ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_smtp_port" );
    exit( 0 );
  }

  port = get_kb_item( "Services/smtp" );
  if( port )
    default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( smtp_is_fragile_port( port:default ) )
    exit( 0 );

  # TBD: Also check for get_smtp_is_marked_wrapped?
  if( get_smtp_is_marked_broken( port:default ) )
    exit( 0 );

  if( ! get_port_state( default ) )
    exit( 0 );

  return default;
}

# @brief Returns the info if a remote SMTP server was internally (in the KB)
#        marked as "broken". It will also save the information in an internal
#        array to avoid that redis is queried again for the same info.
#
# @param port The port of the remote SMTP server.
#
# @return TRUE if the remote SMTP server was marked as broken, FALSE otherwise and
#         NULL in the case where the port parameter wasn't passed.
#
function get_smtp_is_marked_broken( port ) {

  local_var port;
  local_var marked_broken_list, marked_broken;
  # nb: _smtp_is_broken_array is a global_var (see on top)

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_smtp_is_marked_broken" );
    return NULL;
  }

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( _smtp_is_broken_array[port] ) ) {
    if( _smtp_is_broken_array[port] )
      return TRUE;
    else
      return FALSE;
  }

  marked_broken = get_kb_item( "smtp/" + port + "/is_broken" );
  if( marked_broken ) {
    _smtp_is_broken_array[port] = TRUE;
  } else {
    _smtp_is_broken_array[port] = FALSE;
    marked_broken = FALSE;
  }
  return marked_broken;
}

# @brief Sets if a remote SMTP server should be marked as "broken" to other NVTs.
#        The status is set within the following KB entries:
#        "smtp/" + port + "/is_broken" and "smtp/is_broken".
#
# @param port The port of the remote SMTP server.
#
# @return TRUE if the status was successfully saved within the KB and
#         NULL if no port parameter was passed.
#
function set_smtp_is_marked_broken( port ) {

  local_var port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#set_smtp_is_marked_broken" );
    return NULL;
  }

  set_kb_item( name:"smtp/is_broken", value:TRUE );
  set_kb_item( name:"smtp/" + port + "/is_broken", value:TRUE );
  _smtp_is_broken_array[port] = TRUE;
  return TRUE;
}

# @brief Returns the info if a remote SMTP server was internally (in the KB)
#        marked as "wrapped". It will also save the information in an internal
#        array to avoid that redis is queried again for the same info.
#
# @param port The port of the remote SMTP server.
#
# @return TRUE if the remote SMTP server was marked as wrapped, FALSE otherwise and
#         NULL in the case where the port parameter wasn't passed.
#
function get_smtp_is_marked_wrapped( port ) {

  local_var port;
  local_var marked_wrapped_list, marked_wrapped;
  # nb: _smtp_is_wrapped_array is a global_var (see on top)

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_smtp_is_marked_wrapped" );
    return NULL;
  }

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( _smtp_is_wrapped_array[port] ) ) {
    if( _smtp_is_wrapped_array[port] )
      return TRUE;
    else
      return FALSE;
  }

  marked_wrapped = get_kb_item( "smtp/" + port + "/is_wrapped" );
  if( marked_wrapped ) {
    _smtp_is_wrapped_array[port] = TRUE;
  } else {
    _smtp_is_wrapped_array[port] = FALSE;
    marked_wrapped = FALSE;
  }
  return marked_wrapped;
}

# @brief Sets if a remote SMTP server should be marked as "wrapped" to other NVTs.
#        The status is set within the following KB entries:
#        "smtp/" + port + "/is_wrapped" and "smtp/is_wrapped".
#
# @param port The port of the remote SMTP server.
#
# @return TRUE if the status was successfully saved within the KB and
#         NULL if no port parameter was passed.
#
function set_smtp_is_marked_wrapped( port ) {

  local_var port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#set_smtp_is_marked_wrapped" );
    return NULL;
  }

  set_kb_item( name:"smtp/is_wrapped", value:TRUE );
  set_kb_item( name:"smtp/" + port + "/is_wrapped", value:TRUE );
  _smtp_is_wrapped_array[port] = TRUE;
  return TRUE;
}

# @brief Returns the "third party" domain the user has configured within smtp_settings.nasl. To avoid querying
#        the KB for the same info again it will be cached within an internal variable.
#
# @return A string containing the "third party" domain the user has configured within smtp_setting.nasl
#         or "example.com" in the case where the default was kept in smtp_settings.nasl or the VT wasn't
#         included in the scan configuration.
#
function get_3rdparty_domain() {

  local_var domain;
  # nb: __3rdparty_domain is a global var

  if( ! isnull( __3rdparty_domain ) ) {
    domain = string( __3rdparty_domain );
  } else {
    domain = get_kb_item( "Settings/third_party_domain" );
    if( ! isnull( domain ) ) {
      __3rdparty_domain = string( domain );
    } else {
      domain = "example.com";
      __3rdparty_domain = domain;
    }
  }
  return domain;
}

# @brief Gets the SMTP HELO domain saved within the KB in smtp/port/helo.
#        If no SMTP HELO was found in the KB the function will fallback
#        to the returned value of @ref get_3rdparty_domain.
#
# @param port The port of the remote SMTP server to get the HELO from.
#
# @note Add a dependency to check_smtp_helo.nasl if you want to use this function.
#
# @return The SMTP HELO domain or NULL in the case where the port parameter wasn't passed.
#
function get_smtp_helo_from_kb( port ) {

  local_var port, helo;
  # nb: __smtp_helo is a global var

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_smtp_helo_from_kb" );
    return NULL;
  }

  if( ! isnull( __smtp_helo ) ) {
    helo = string( __smtp_helo );
  } else {
    helo = get_kb_item( "smtp/"+ port + "/helo" );
    if( ! isnull( helo ) ) {
      __smtp_helo = string( helo );
    } else {
      helo = get_3rdparty_domain();
      __smtp_helo = helo;
    }
  }
  return helo;
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