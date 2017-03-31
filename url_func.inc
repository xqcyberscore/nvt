###############################################################################
# OpenVAS Vulnerability Test
# $Id: url_func.inc 3776 2016-07-30 09:01:30Z cfi $
#
# Collection of functions to handle URLs
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
# URL encode & decode functions: Chandan S(schandan@secpod.com)
#
# Copyright:
# Copyright (C) 2008 Vlatko Kosturjak
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
# $Revision: 3776 $
#
###############################################################################

global_var HEX_LOWERCASE, HEX_UPPERCASE;
HEX_LOWERCASE=1;
HEX_UPPERCASE=2;

# function taken from amap.nasl which is GPL
function url_hex2raw( s ) {

  local_var s, i, j, ret, l;

  if( ! s ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#s#-#url_hex2raw" );

  s = chomp( s ); # remove trailing blanks, CR, LF...
  l = strlen( s );
  if( l % 2 ) display( "hex2raw: odd string: ", s, "\n" );
  for( i = 0; i < l; i += 2 ) {
    if( ord( s[i] ) >= ord( "0" ) && ord( s[i] ) <= ord( "9" ) ) {
      j = int(s[i]);
    } else {
      j = int( ( ord( s[i] ) - ord( "a" ) ) + 10 );
    }

    j *= 16;
    if( ord( s[i+1] ) >= ord( "0" ) && ord( s[i+1] ) <= ord( "9" ) ) {
      j += int(s[i+1]);
    } else {
      j += int( ( ord( s[i+1] ) - ord( "a" ) ) + 10 );
    }
    ret += raw_string( j );
  }
  return ret;
}

###############################################################
# Function Name 'urlencode'
###############################################################

function urlencode( str, unreserved ) {

  local_var i, j, str, estr, char_set, num_set, specl_char_set, unreserv_chars, unreserved, flag;

  if( ! str ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#urlencode" );

  char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  num_set = "0123456789";
  specl_char_set = "_-.!~*'()";
  unreserv_chars = char_set + num_set + specl_char_set;

  if( unreserved != NULL ) {
    unreserv_chars = unreserv_chars + unreserved;
  }

  for( i = 0; i < strlen( str ); i++ ) {
    flag = "non_word";

    # Encode on any non word character
    for( j = 0; j < strlen( unreserv_chars ); j++ ) {
      if( str[i] == unreserv_chars[j] ) {
        flag = "word";
        break;
      }
    }

    if( flag == "non_word" ) {
      estr = estr + '%' + hexstr( str[i] );
    } else {
      estr = estr + str[i];
    }
  }
  return( estr );
}

###############################################################
# Function Name 'urldecode'
###############################################################

function urldecode( estr ) {

  local_var estr, dstr, i;

  if( ! estr ) set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#estr#-#urldecode" );

  for( i = 0; i < strlen( estr ); i++ ) {
    if( estr[i] == '%' ) {
      dstr = dstr + url_hex2raw( s:tolower( estr[i+1] + estr[i+2] ) );
      i = i + 2;
    } else if( estr[i] == '+' ) {
      dstr = dstr + ' ';
      i = i + 1;
    } else {
      dstr = dstr + estr[i];
    }
  }
  dstr = ereg_replace( string:dstr, pattern:"<!--(.|\n)*-->", replace:"", icase:TRUE );
  return( dstr );
}
