###############################################################################
# OpenVAS Include File
# $Id: sip.inc 13723 2019-02-18 08:22:05Z cfischer $
#
# functions to support sip
#
# Authors:
# Ferdy Riphagen <f.riphagen@nsec.nl>
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen <f.riphagen@nsec.nl>
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
# $Revision: 13723 $
#
###############################################################################

# @brief Creates a SIP OPTIONS request, sends the request to the target, receives the
#        response and extracts the SIP header (banner) from the response. If a header
#        was received it is saved into the knowledge base. If a header was requested
#        which was requested previously the cached header will be returned instead of
#        doing a new request.
#
# @param port  The SIP port of the target.
# @param proto The (optional) IP Protocol ("tcp" or "udp") to be used. Defaults to "udp"
#              if not passed.
#
# @return The SIP header of the remote host, FALSE if no response or header/banner was received and NULL if no port parameter was passed.
#
function get_sip_banner( port, proto ) {

  local_var port, proto;
  local_var banner, opt, res, _banner;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_sip_banner" );
    return NULL;
  }

  if( ! proto )
    proto = "udp";

  banner = get_kb_item( "sip/banner/" + proto + "/" + port );
  if( banner )
    return banner;

  opt = construct_sip_options_req( port:port, proto:proto );
  res = sip_send_recv( port:port, data:opt, proto:proto );

  if( ! res || "SIP/2.0" >!< res )
    return FALSE;

  if( "Server:" >< res ) {
    banner = egrep( pattern:'^Server:', string:res );
    banner = substr( banner, 8 );
  }

  if( "User-Agent:" >< res ) {
    _banner = egrep( pattern:'^User-Agent:', string:res );
    _banner = substr( _banner, 12 );
    if( banner )
      banner += '\n';
    banner += _banner;
  }

  banner = chomp( banner );

  if( banner ) {
    replace_kb_item( name:"sip/banner/" + proto + "/" + port, value:banner );
    return banner;
  } else {
    return FALSE;
  }
}

# @brief Sends a SIP packet to the remote service and returns the received response.
#
# @param port  The SIP port of the target.
# @param data  The request to sent (e.g. created via @ref construct_sip_options_req).
# @param proto The (optional) IP Protocol ("tcp" or "udp") to be used. Defaults to "udp"
#              if not passed.
#
# @return The received response, FALSE if no response was received and NULL if no port parameter was passed.
#
function sip_send_recv( port, data, proto ) {

  local_var port, data, proto;
  local_var soc, res;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#sip_send_recv" );
    return NULL;
  }

  if( ! data )
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#sip_send_recv" );

  if( ! proto )
    proto = "udp";

  soc = open_sip_socket( port:port, proto:proto );
  if( ! soc )
    return FALSE;

  send( socket:soc, data:data );
  res = recv( socket:soc, length:1024 );
  close( soc );

  res = chomp( res );

  if( res )
    return res;
  else
    return FALSE;
}

# @brief Sends a SIP packet to the remote service and tries to check if the service is still alive.
#
# @param port  The SIP port of the target.
# @param proto The (optional) IP Protocol ("tcp" or "udp") to be used. Defaults to "udp"
#              if not passed.
# @param retry The mount of retries to use. Defaults to 2 if not passed.
#
# @return TRUE if the service is still alive, FALSE otherwise and NULL if no port parameter was passed.
#
function sip_alive( port, proto, retry ) {

  local_var port, proto, retry;
  local_var i, soc, res, opt;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#sip_alive" );
    return NULL;
  }

  if( ! proto ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#sip_alive" );
    proto = "udp";
  }

  if( ! retry )
    retry = 2;

  i = 0;

  soc = open_sip_socket( port:port, proto:proto );

  while( ! soc && i++ < retry ) {
    sleep( 1 );
    soc = open_sip_socket( port:port, proto:proto );
  }

  if( ! soc )
    return FALSE;

  opt = construct_sip_options_req( port:port, proto:proto );

  send( socket:soc, data:opt );
  res = recv( socket:soc, length:1024 );
  close( soc );

  if( ! res )
    return FALSE;

  if( "SIP/2.0" >< res )
    return TRUE;
  else
    return FALSE;
}

function construct_sip_options_req( port, proto ) {

  local_var opt, port, proto;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#construct_sip_options_req" );
    port = "5060";
  }

  if( ! proto ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#construct_sip_options_req" );
    proto = "udp";
  }

  opt = "OPTIONS sip:openvas@" + get_host_name() + ":" + port + " SIP/2.0" + '\r\n' +
        "Via: SIP/2.0/" + toupper( proto ) + " " + this_host() + ":" + port + '\r\n' +
        "Max-Forwards: 70" + '\r\n' +
        "To: <sip:openvas@" + get_host_name() + ":" + port + ">" + '\r\n' +
        "From: OpenVAS <sip:openvas@" + this_host() + ":" + port + ">;tag=" + rand() + '\r\n' +
        "Call-ID: " + rand() + '\r\n' +
        "CSeq: 63104 OPTIONS" + '\r\n' +
        "Contact: <sip:openvas@" + this_host() + ":" + port + ">" + '\r\n' +
        "Accept: application/sdp" + '\r\n' +
        "Content-Length: 0" + '\r\n\r\n';

  return opt;

}

function open_sip_socket( port, proto ) {

  local_var soc, port, proto;

  if( ! port ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#open_sip_socket" );
    return;
  }

  if( ! proto ) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#open_sip_socket" );
    proto = "udp";
  }

  if( proto == "tcp" ) {
    if( ! get_port_state( port ) ) return FALSE;
    soc = open_sock_tcp( port );
    if( ! soc ) return FALSE;
  } else {
    if( ! get_udp_port_state( port ) ) return FALSE;
    if( islocalhost() ) {
      soc = open_sock_udp( port );
    } else {
      soc = open_priv_sock_udp( sport:5060, dport:port );
    }
    if( ! soc ) return FALSE;
  }

  return soc;

}

function get_sip_port_proto( default_port, default_proto ) {

  local_var default_port, default_proto, port_and_proto, x, x_port, x_proto, ret_arr;

  if( ! default_port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default_port#-#get_sip_port_proto" );
  if( ! default_proto ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default_proto#-#get_sip_port_proto" );

  port_and_proto = get_kb_item( "sip/port_and_proto" ); # this could fork, syntax e.g.: 5060#-#udp
  if( port_and_proto ) {
    x = split( port_and_proto, sep:'#-#', keep:FALSE );
    x_port  = x[0];
    x_proto = x[1];
  } else {
    x_port  = default_port;
    x_proto = default_proto;
  }

  if( x_proto == "udp" ) {
    if( ! get_udp_port_state( x_port ) ) exit( 0 );
  } else {
    if( ! get_port_state( x_port ) ) exit( 0 );
    # Includes e.g. PJL ports which are printing everything
    # sent to them so exit for such a port here
    if( sip_is_fragile_port( port:x_port ) ) exit( 0 );
  }

  ret_arr['port'] = x_port;
  ret_arr['proto'] = x_proto;

  return ret_arr;

}

# Duplicated from misc_func.inc
function sip_is_fragile_port( port ) {

  local_var port, fragile_ports, fragile_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#telnet_is_fragile_port" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports ) return;

  foreach fragile_port( fragile_ports ) {
    if( port == fragile_port ) return TRUE;
  }

  return;
}
