###############################################################################
# OpenVAS Vulnerability Test
# $Id: imap_func.inc 4042 2016-09-13 05:49:25Z cfi $
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
# $Revision: 4042 $
#
###############################################################################

function get_imap_banner( port ) {

  local_var sb, banner, soc;

  if( ! port ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_imap_banner" );
  
  sb = "imap/banner/" + port;
  banner = get_kb_item( sb );
  if( banner ) return( banner );
  if( get_kb_item( "imap/" + port + "/broken" ) )
    return ( 0 );

  if( ! get_port_state( port ) ) return ( 0 );
  soc = open_sock_tcp( port );
  if( ! soc ) {
    set_kb_item( name:"imap/" + port + "/broken", value:TRUE );
    return ( 0 );
  }
  banner = recv_line( socket:soc, length:4096 );
  close( soc );
  if( ! banner ) {
    set_kb_item( name:"imap/" + port + "/broken", value:TRUE );
    return ( 0 );
  }
  
  replace_kb_item( name:sb, value:banner );
  return( banner );
}

function get_imap_port( default ) {

  local_var default, port, p;

  if( ! default ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#get_imap_port" );

  port = get_kb_item( "Services/imap" );
  if( port ) default = port;

  # PJL ports printing everything sent to them
  # so exit for such a port here
  if( imap_is_pjl_port( port:default ) ) exit( 0 );

  p = get_kb_item( "imap/" + default + "/broken" );
  if( p ) exit( 0 );

  if( ! get_port_state( default ) ) exit( 0 );

  return default;
}

# Duplicated from misc_func.inc
function imap_is_pjl_port( port ) {

  local_var port, pjl_ports, pjl_port;

  if( ! port ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#imap_is_pjl_port" );
    return;
  }

  pjl_ports = get_kb_list( 'Services/PJL' );
  if( ! pjl_ports ) return;

  foreach pjl_port( pjl_ports ) {
    if( port == pjl_port ) return TRUE;
  }

  return;
}