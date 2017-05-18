###############################################################################
# OpenVAS Vulnerability Test
# $Id: snmp_func.inc 5939 2017-04-11 16:02:44Z mime $
#
# Functions for SNMP
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
# $Revision: 5939 $
#
###############################################################################

valid_snmpv3_errors = make_list( "Unknown user name",
                                 "Unsupported security level",
                                 "Generic error",
                                 "Session abort failure",
                                 "Unknown security model in message",
                                 "MIB not initialized",
                                 "Authentication failure (incorrect password, community or key)");

global_var snmp_error, v3_creds, valid_snmpv3_errors, last_snmp_error;

function check_snmpv1( port, community )
{
  if( ! port ) return;
  if( ! community ) return;

  oid = '1.3.6.1.2.1.1.1.0';
  protocol = 'udp';

  ret = snmpv1_get( port:port, oid:oid, protocol:protocol, community: community );
  if( ret[0] < 0 ) return;

  if( ret[0] == 0 && ! isnull( ret[1] ) ) return TRUE;

  return;

}

function check_snmpv2( port, community )
{
  if( ! port ) return;
  if( ! community ) return;

  oid = '1.3.6.1.2.1.1.1.0';
  protocol = 'udp';

  ret = snmpv2c_get( port:port, oid:oid, protocol:protocol, community: community );
  if( int( ret[0] ) < 0 ) return;

  if( ret[0] == 0 && ! isnull( ret[1] ) ) return TRUE;

  return;

}

function check_snmpv3( port )
{
  if( ! port ) return;

  oid = '1.3.6.1.2.1.1.1.0';
  protocol = 'udp';

  snmpv3_username = get_kb_item("SNMP/V3/username");
  if (!snmpv3_username || (strlen(snmpv3_username) == 0)) {
    # Set some credentials to test for SNMPv3
    snmpv3_username = 'openvas';
    snmpv3_password = 'openvaspass';
    snmpv3_authalgo = 'md5';
    snmpv3_privpass = 'openvaspass';
    snmpv3_privalgo = 'des';
  }
  else {
    snmpv3_password = get_kb_item("SNMP/V3/password");
    snmpv3_authalgo = get_kb_item("SNMP/V3/auth_algorithm");
    if (!snmpv3_privpass = get_kb_item("SNMP/V3/privacy_password"))
      snmpv3_privalgo = NULL;
    else
      snmpv3_privalgo = get_kb_item("SNMP/V3/privacy_algorithm");

    v3_creds = TRUE;
  }

  ret = snmpv3_get( port:port, protocol:protocol, username: snmpv3_username, oid:oid,
                   authpass: snmpv3_password, authproto: snmpv3_authalgo, privpass: snmpv3_privpass,
                   privproto: snmpv3_privalgo );

  if( ret[0] == -1 )
  {
    snmp_error = ret[1];
    if( in_array( array:valid_snmpv3_errors, search:snmp_error ) )
      return 2;
    else
      return;
  }

  if( ret[0] == 0 && ! isnull( ret[1] ) ) return 1;

  return;
}

function snmp_get( port, oid, version, community ) {

  local_var port, oid, version, community, ret;
  local_var v3_username, v3_password, v3_authalgo, v3_privpass, v3_privalgo;

  if (!defined_func("snmpv3_get"))
    return;

  if (!port) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#snmp_get" );
    return;
  }

  if (!oid) {
    set_kb_item( name: "nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#oid#-#snmp_get" );
    return;
  }

  if (!version)
    version = get_kb_item("SNMP/prefered_version");

  if( ! version ) return;

  if (version == 3) {
    if( get_kb_item( "SNMP/V3/working" ) ) {
      v3_username = get_kb_item("SNMP/V3/username");
      v3_password = get_kb_item("SNMP/V3/password");
      v3_authalgo = get_kb_item("SNMP/V3/auth_algorithm");
      v3_privpass = get_kb_item("SNMP/V3/privacy_password");
      v3_privalgo = get_kb_item("SNMP/V3/privacy_algorithm");

      if (v3_username && v3_username != "") {
        if (!v3_privpass)
          v3_privalgo = NULL;

        ret = snmpv3_get(port: port, protocol: "udp", username: v3_username, oid: oid,
                         authpass: v3_password, authproto: v3_authalgo, privpass: v3_privpass,
                         privproto: v3_privalgo );

        if (ret[0] != 0 || snmp_is_error_message( ret[1] ) ) {
          last_snmp_error = ret[1];
          return;
        }

        if (ret[0] == 0 && ! snmp_is_error_message( ret[1] ))
          return snmp_clean_ret( ret[1] );
      }
    }
  }

  if (version == 2) {
    if( get_kb_item( "SNMP/V2/working" ) ) {
      if (!community)
        community = get_community( version:2 );
      if (community && community != "") {
        ret = snmpv2c_get(port: port, oid: oid, protocol: "udp", community: community);

        if (ret[0] != 0 || snmp_is_error_message( ret[1] ) ) {
          last_snmp_error = ret[1];
          return;
        }

        if (ret[0] == 0 && ! snmp_is_error_message( ret[1] ) )
          return snmp_clean_ret( ret[1] );
      }
    }
  }

  if (version == 1) {
    if( get_kb_item( "SNMP/V1/working" ) ) {
      if (!community)
        community = get_community( version:1 );
      if (community && community != "") {
        ret = snmpv1_get(port: port, oid: oid, protocol: "udp", community: community);
        if (ret[0] != 0 || snmp_is_error_message( ret[1] ) ) {
          last_snmp_error = ret[1];
          return;
        }
        if (ret[0] == 0 && ! snmp_is_error_message( ret[1] ) )
          return snmp_clean_ret( ret[1] );
      }
    }
  }

  return;
}

function snmp_clean_ret()
{
  arg = _FCT_ANON_ARGS[0];
  if( ! arg ) return;

  return ereg_replace( pattern:'^"(.*)"$', string:arg, replace:"\1" );
}

function get_community( version )
{
  if( ! version ) return;

  if( version  == 1 )
    ckey = 'SNMP/community';
  else if (version  == 2 )
    ckey = "SNMP/V2/community";
  else 
    return;

  clist = get_kb_list( ckey );

  if( ! clist ) return;

  clist = make_list( clist );

  return clist[ 0 ];

}

function snmp_is_error_message()
{
  local_var message, errors, error;

  message = _FCT_ANON_ARGS[0];

  if( ! message )
    return;

  errors = make_list(
                     "No Such Object available on this agent at this OID",
                     "No Such Instance"
                     );

  foreach error ( errors )
  {
    if( error >< message )
      return TRUE;
  }

  return;
}

