###############################################################################
# OpenVAS Vulnerability Test
# $Id: byte_func.inc 4659 2016-12-02 11:02:03Z cfi $
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
#
# $Revision: 4659 $
#
###############################################################################

global_var BYTE_ORDER;

# Little-endian byte order
BYTE_ORDER_LITTLE_ENDIAN = 1;
# Big-endian byte order
BYTE_ORDER_BIG_ENDIAN    = 2;
# Set default
BYTE_ORDER = BYTE_ORDER_BIG_ENDIAN;

function mkbyte() {

  local_var value, byte;

  value = _FCT_ANON_ARGS[0];

  if( isnull( value ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#mkbyte" );

  byte = raw_string( 0xFF & value );
  return byte;
}

function mkword() {

  local_var value, DATA;

  value = _FCT_ANON_ARGS[0];

  if( isnull( value ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#mkword" );
    return 0;
  }

  if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ) {
    DATA = raw_string( ( value >> 8 ) & 255, value & 255 );
  } else {
    DATA = raw_string( value & 255, (value >> 8) & 255 );
  }
  return DATA;
}

function set_byte_order() {

  local_var arg;

  arg = _FCT_ANON_ARGS[0];

  if( ! isnull( arg ) ) {
    if( arg == BYTE_ORDER_BIG_ENDIAN || arg == BYTE_ORDER_LITTLE_ENDIAN ) {
      BYTE_ORDER = arg;
    }
  } else {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#set_byte_order" );
  }
}

function mkdword() {

  local_var value, DATA;

  value = _FCT_ANON_ARGS[0];

  if( isnull( value ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#mkdword" );
    return 0;
  }

  if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ) {
    DATA = raw_string( ( value >> 24 ) & 255, ( value >> 16 ) & 255, ( value >>  8 ) & 255, ( value ) & 255 );
  } else {
    DATA = raw_string( value & 255, ( value >> 8 ) & 255, ( value >> 16 ) & 255, ( value >> 24 ) & 255 );
  }
  return DATA;
}

function mkpad() {

  local_var length, DATA, arg;

  arg = _FCT_ANON_ARGS[0];

  if( isnull( arg ) ) {
    length = 1000;
  } else {
    length = arg;
  }

  DATA = crap( data:raw_string( 0x00 ), length:length );
  return DATA;
}

function getword( blob, pos ) {

  local_var DATA, blob, pos;

  if( isnull( blob) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#blob#-#getword" );

  if( ! pos ) pos = 0;

  if( ! blob = substr( blob, pos ) ) return 0;

  if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ) {
    DATA = ord( blob[0] ) << 8 | ord( blob[1] );
  } else {
    DATA = ord( blob[0] ) | ord( blob[1] ) << 8;
  }
  return DATA;
}

function getdword( blob, pos ) {

  local_var DATA, blob, pos;

  if( isnull( blob ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#blob#-#getdword" );

  if( ! pos ) pos = 0;

  if( ! blob = substr( blob, pos ) ) return 0;

  if( BYTE_ORDER == BYTE_ORDER_BIG_ENDIAN ) {
    DATA = ord( blob[0] ) << 24 | ord( blob[1] ) << 16 | ord( blob[2] ) << 8 | ord( blob[3] );
  }  else {
    DATA = ord( blob[0] ) | ord( blob[1] ) << 8 | ord( blob[2] ) << 16 | ord( blob[3] ) << 24;
  }
  return DATA;
}

function dec2bin( dec ) {

  local_var dnum, res, dec;

  if( isnull( dec ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#dec#-#dec2bin" );

  dnum = int( dec );

  if( dnum == 0 )
    return dnum;

  while( dnum > 0 ) {
    res = string( dnum & 1 ) + res;
    dnum = dnum >>= 1;
  }

  while( strlen( res ) < 8 ) {
    res = string( 0 ) + res;
  }
  return res;
}
