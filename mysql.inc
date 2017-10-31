###############################################################################
# OpenVAS Include File
# $Id: mysql.inc 7578 2017-10-26 11:00:21Z cfischer $
#
# Functions for MySQL
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Christian Fischer <christian.fischer@greenbone.net>
# Unknown author of set/get_*_version functions
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
# $Revision: 7578 $
#
###############################################################################

global_var ER_HOST_IS_BLOCKED, ER_HOST_NOT_PRIVILEGED;

# https://dev.mysql.com/doc/refman/5.7/en/error-messages-server.html
ER_HOST_IS_BLOCKED = 1129;
ER_HOST_NOT_PRIVILEGED = 1130;

function set_mysql_version( port, version ) {

  local_var port, version;

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#set_mysql_version" );
  if( ! version ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#set_mysql_version" );

  set_kb_item( name:"mysql/version/" + port, value:version );
}

function get_mysql_version( port ) {

  local_var port;

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_mysql_version" );

  return get_kb_item( "mysql/version/" + port );
}

function set_mariadb_version( port, version ) {

  local_var port, version;

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#set_mariadb_version" );
  if( ! version ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#set_mariadb_version" );

  set_kb_item( name:"mariadb/version/" + port, value:version );
}

function get_mariadb_version( port ) {

  local_var port;

  if( ! port ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_mariadb_version" );

  return get_kb_item( "mariadb/version/" + port );
}

function recv_mysql_server_handshake( soc ) {

  local_var soc, buf, plen;

  if( ! soc ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#recv_mysql_server_handshake" );
    exit( 0 );
  }

  buf = recv( socket:soc, length:4 );
  if( ! buf || strlen( buf ) != 4 ) {
    close( soc );
    exit( 0 );
  }

  # https://dev.mysql.com/doc/internals/en/client-server-protocol.html
  # Packet Length
  plen = ord( buf[0] ) + ( ord( buf[1] ) / 8 ) + ( ord( buf[2] ) / 16 );

  # The first packet of a client query will have Packet Number = 0
  if( ord( buf[3] ) != 0 ) {
    close( soc );
    exit( 0 );
  }

  buf = recv( socket:soc, length:plen );
  if( strlen( buf ) != plen ) {
    close( soc );
    exit( 0 );
  }
  return buf;
}