###############################################################################
# OpenVAS Include File
# $Id: imap_func.inc 7922 2017-11-28 10:06:28Z cfischer $
#
# Support methods for IMAP
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

function get_imap_banner( port ) {

  local_var port, sb, banner, soc, idbanner, request;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_imap_banner" );
  
  sb = "imap/banner/" + port;
  banner = get_kb_item( sb );
  if( banner ) return( banner );
  if( get_kb_item( "imap/" + port + "/broken" ) )
    return NULL;

  if( ! get_port_state( port ) ) return NULL;
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_kb_item( name:"imap/" + port + "/broken", value:TRUE );
    return NULL;
  }
  banner = recv_line( socket:soc, length:4096 );
  if( ! banner ) {
    close( soc );
    set_kb_item( name:"imap/" + port + "/broken", value:TRUE );
    return NULL;
  }

  # Request to get a version for e.g. Cyrus-IMAP:
  # 01 ID ("name" "MailMate" "version" "r3255" "vendor" "Freron Software" "contact" "imap-id@freron.com")
  # Responses are e.g.
  # ID ("name" "dbmail" "version" "0.9.9" "os" "Linux" "os-version" "3.2.12-gentoo")
  # ID ("name", "Bigfoot", "version", "1.0", "os", "Linux", "os-version", "2.6",
  # nb: A few systems / implementation are replying with a "NO Only one Id allowed in non-authenticated state"
  # until an authenticated request is done in between. So this is not absolutely reliable.
  request = '01 ID ("name" "OpenVAS" "version" "' + OPENVAS_VERSION + '" "vendor" "OpenVAS" "contact" "openvas@example.com")\r\n';
  send( socket:soc, data:request );
  idbanner = recv_line( socket:soc, length:4096 );
  if( "ID" >< idbanner && "ID NIL" >!< idbanner ) {
    banner += idbanner;
  }

  close( soc );
  replace_kb_item( name:sb, value:banner );
  return banner;
}

function get_imap_port( default ) {

  local_var default, port, p;

  if( ! default ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_imap_port" );

  port = get_kb_item( "Services/imap" );
  if( port ) default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if( imap_is_fragile_port( port:default ) ) exit( 0 );

  p = get_kb_item( "imap/" + default + "/broken" );
  if( p ) exit( 0 );

  if( ! get_port_state( default ) ) exit( 0 );

  return default;
}

# Duplicated from misc_func.inc
function imap_is_fragile_port( port ) {

  local_var port, fragile_ports, fragile_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#imap_is_fragile_port" );
    return;
  }

  fragile_ports = get_kb_list( "Services/fragile_port" );
  if( ! fragile_ports ) return;

  foreach fragile_port( fragile_ports ) {
    if( port == fragile_port ) return TRUE;
  }

  return;
}