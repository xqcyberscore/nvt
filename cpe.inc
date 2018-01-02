###############################################################################
# OpenVAS Vulnerability Test
# $Id: cpe.inc 8211 2017-12-21 10:38:01Z cfischer $
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
# $Revision: 8211 $
#
###############################################################################

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

  res = eregmatch(string:value, pattern:exp, icase:TRUE);
  if (res[1]) {
    last = strlen(base) - 1;
    if (":" >!< base[last]) {
      return base;
    } else if (res[1] && res[2]) {
      return string(base, res[1], ":", res[2]);
    } else if (res[1]) {
      return string(base, res[1]);
    }
  }
  return NULL;
}

## Function to Register Product and Build report
function register_and_report_cpe( app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra ) {

  local_var app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra;

  if( isnull( cpename ) && ( isnull( base ) || isnull( expr ) ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpename,base,expr#-#register_and_report_cpe" );
    return NULL;
  }

  ## setting location if location variable value is null
  if( ! insloc ) insloc = "unknown";

  ## setting concluded if value is null
  if( ! concluded && ver ) concluded = ver;

  ## setting version to unknown if not available
  if( ! ver || ver == "" ) ver = "unknown";

  if( ! regProto ) regProto = "tcp";

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
    return NULL;
  }
}
