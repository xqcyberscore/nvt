###############################################################################
# OpenVAS Vulnerability Test
# $Id: cpe.inc 7580 2017-10-26 11:16:36Z cfischer $
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
# $Revision: 7580 $
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
function build_report(app, ver, concluded, cpe, base, exp, insloc, port, conclUrl, extra)
{

  ## setting location if location variable value is null
  if(!insloc)
   insloc = "Could not find the install location";
  
  if(base && exp)
  {
    cpe = build_cpe(value:ver, exp:exp, base:base);
    if(isnull(cpe))
      exit(0);
  }

  if(port)
    register_product(cpe:cpe, location:insloc, port:port);
  else
    register_product(cpe:cpe, location:insloc);

  if(!concluded){
    concluded = ver;
  }

  log_message(data: build_detection_report(app:app,
                                           version:ver,
                                           install:insloc,
                                           cpe:cpe,
                                           extra: extra,
                                           concluded:concluded,
                                           concludedUrl:conclUrl),
                                           port:port);
}

## Function to Register Product and Build report
function register_cpe(tmpVers, tmpExpr, tmpBase, insloc, app, port, concluded)
{
  local_var cpe;

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
  if(cpe){
    build_report(app, ver:tmpVers, concluded:tmpVers, cpe, insloc, port);
  }
}

## Function to Register Product and Build report
function register_and_report_cpe( app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra ) {

  local_var app, ver, concluded, cpename, base, expr, insloc, regPort, regService, regProto, conclUrl, extra;

  if( isnull( cpename ) && ( isnull( base ) || isnull( expr ) ) ) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#cpename,base,expr#-#register_and_report_cpe" );
    return NULL;
  }

  ## setting location if location variable value is null
  if( ! insloc ) insloc = "undefined";

  ## setting concluded if value is null
  if( ! concluded && ver ) concluded = ver;

  ## setting Version unknown if not available
  if( ! ver ) ver = "unknown";

  if( ! regProto ) regProto = "tcp";

  ##Build CPE
  if( ! cpename && base ) {
    cpename = build_cpe( value:ver, exp:expr, base:base );
    if(tolower(ver) == "unknown") {
      cpename = base ;
    }
  }

  if(cpename)
  {
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
