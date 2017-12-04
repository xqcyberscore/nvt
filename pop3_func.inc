###############################################################################
# OpenVAS Include File
# $Id: pop3_func.inc 7922 2017-11-28 10:06:28Z cfischer $
#
# Methods for handling POP3
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 2004 Anonymous
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

function get_pop3_banner( port ) {

  local_var port, sb, banner, soc, capabanner, implbanner;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_pop3_banner" );

  sb = "pop3/banner/" + port;
  banner = get_kb_item( sb );
  if( banner ) return banner;
  if( get_kb_item( "pop3/" + port + "/broken" ) )
    return NULL;

  if( ! get_port_state( port ) ) return NULL;
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_kb_item( name:"pop3/" + port + "/broken", value:TRUE );
    return NULL;
  }
  banner = recv_line( socket:soc, length:4096 );
  if( ! banner ) {
    close( soc );
    set_kb_item( name:"pop3/" + port + "/broken", value:TRUE );
    return NULL;
  }

  # nb: This part is used to catch the software from the "CAPA" request.
  # e.g. the initial banner is only: POP3 banner is +OK POP3 server ready <example@example.com>
  # but the CAPA request is exposing the software version: IMPLEMENTATION Smartertools_SmarterMail_1.5
  send( socket:soc, data:'CAPA\r\n' );
  capabanner = recv_line( socket:soc, length:4096 );
  if( "capability list follows" >< tolower( capabanner ) || "List of capabilities follows" >< tolower( capabanner ) ||
      "capa list follows" >< tolower( capabanner ) || "list follows" >< capabanner ) {
    while( capabanner = recv_line( socket:soc, length:4096 ) ) {
      implbanner = egrep( pattern:"IMPLEMENTATION .*", string:capabanner );
      if( implbanner ) {
        banner += implbanner;
        break;
      }
    }
  }
  close( soc );
  replace_kb_item( name:sb, value:banner );
  return banner;
}

function get_pop3_port( default ) {

  local_var default, port, p;

  if( ! default ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_pop3_port" );

  port = get_kb_item( "Services/pop3" );
  if( port ) default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( pop3_is_fragile_port( port:default ) ) exit( 0 );

  p = get_kb_item( "pop3/" + default + "/broken" );
  if( p ) exit( 0 );

  if( ! get_port_state( default ) ) exit( 0 );

  return default;
}

# Duplicated from misc_func.inc
function pop3_is_fragile_port( port ) {

  local_var port, fragile_ports, fragile_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#pop3_is_fragile_port" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports ) return;

  foreach fragile_port( fragile_ports ) {
    if( port == fragile_port ) return TRUE;
  }

  return;
}