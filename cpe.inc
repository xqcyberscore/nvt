###############################################################################
# OpenVAS Vulnerability Test
# $Id: cpe.inc 10707 2018-08-01 10:58:06Z cfischer $
#
# CPE Support Functions
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
#
# Updated By Sharath S <sharaths@secpod.com> On 2009-11-20
#
# Updated By Chandrashekhar B <bchandra@secpod.com>
#            Sharath S <sharaths@secpod.com> On 2009-11-30
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
# $Revision: 10707 $
#
###############################################################################

# @brief Extends a given CPE base (like e.g. cpe:/a:vendor:product:) with
#        a given value if the passed expression in the exp is matching this value.
#
# @param value the value to append to the given CPE base
# @param exp   the regex expression where the given value needs to be match against
# @param base  the CPE base in the form of cpe:/a:vendor:product:
#
# @return A string containing the CPE base with the appended value (if the expression has matched),
#         NULL otherwise.
#
function build_cpe( value, exp, base ) {

  local_var value, exp, base, res, last;

  if( isnull( value ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#build_cpe" );
    return NULL;
  }

  if( isnull( exp ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#exp#-#build_cpe" );
    return NULL;
  }

  if( isnull( base ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#base#-#build_cpe" );
    return NULL;
  }

  res = eregmatch( string:value, pattern:exp, icase:TRUE );
  if( res[1] ) {
    last = strlen(base) - 1;
    if( ":" >!< base[last] ) {
      return base;
    } else if( res[1] && res[2] ) {
      return string(base, res[1], ":", res[2] );
    } else if( res[1] ) {
      return string( base, res[1] );
    }
  }
  return NULL;
}

# @brief Registers a given product CPE with the given info in the knowledge base.
#        Additionally it will build a report message about this detection and sends it via a
#        log_message() to the manager.
#
# @param app        the Name of the App which should be registered, this is included in the report message.
# @param ver        the Version of the App which should be registered.
# @param concluded  the text string where the product detection was concluded from.
# @param cpename    a full CPE string in the form of e.g. cpe:/a:vendor:product or cpe:/a:vendor:product:1.2.3 which should be registered
# @param base       a base CPE string in the form of e.g. cpe:/a:vendor:product: which is used to build a CPE with an appended version
# @param expr       a regex expression which is used to match the ver parameter against and which is added to the base CPE if a match was found.
# @param insloc     the location/URL where the product was detected.
# @param regPort    the Port where the product was detected.
# @param regService the Service (e.g. www, ftp, snmp) where the product was detected.
# @param regProto   the network protocol (e.g. tcp, udp) where the product was detected.
# @param conclUrl   the URL/location where the product was detected from
# @param extra      any extra information which should be added to the report message.
#
function register_and_report_cpe( app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra ) {

  local_var app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra;

  if( isnull( cpename ) && ( isnull( base ) || isnull( expr ) ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpename,base,expr#-#register_and_report_cpe" );
    return NULL;
  }

  if( ! insloc ) insloc = "unknown";
  if( ! concluded && ver ) concluded = ver;
  if( ! ver || ver == "" ) ver = "unknown";
  if( ! regProto ) regProto = "tcp";

  #nb: make sure that we're at least registering a default port to 0
  #for local detections via e.g. SSH
  if( isnull( regPort ) ) regPort = 0;

  if( ! cpename && base ) {
    cpename = build_cpe( value:ver, exp:expr, base:base );
    if( ! cpename ) {
      cpename = ereg_replace( pattern:":$", string:base, replace:"" );
    }
  }

  if( cpename ) {
    register_product( cpe:cpename, location:insloc, port:regPort, proto:regProto, service:regService );

    log_message( data:build_detection_report( app:app,
                                              version:ver,
                                              install:insloc,
                                              cpe:cpename,
                                              extra:extra,
                                              concluded:concluded,
                                              concludedUrl:conclUrl ),
                                              port:regPort,
                                              proto:regProto );
  }
}
