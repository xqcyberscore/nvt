###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_detect_http.nasl 8138 2017-12-15 11:42:07Z cfischer $
#
# AVM FRITZ!Box Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108036");
  script_version("$Revision: 8138 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:42:07 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify an AVM FRITZ!Box via the HTTP
  login page and tries to extract the model and version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

fingerprint["a39b0868ecce7916673a3119c164a268"] = "Fon WLAN;7240";
fingerprint["4ff79300a437d947adce1ecbc5dbcfe9"] = "Fon WLAN;7170";
fingerprint["9adfbf40db1a7594be31c21f28767363"] = "Fon WLAN;7270"; # The 7270, 7270v2 and 7270v3 have the same fingerprint

port = get_http_port( default:80 );
buf = http_get_cache( item:"/", port:port );

if( "FRITZ!Box" >< buf && ( "AVM" >< buf || "logincheck.lua" >< buf || "/cgi-bin/webcm" >< buf ) ) {

  set_kb_item( name:"avm_fritz_box/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/http/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/http/port", value:port );

  type = "unknown";
  model = "unknown";
  fw_version = "unknown";

  mo = eregmatch( pattern:'FRITZ!Box (Fon WLAN|WLAN)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)', string:buf );
  if( ! isnull( mo[1] ) ) type = mo[1];
  if( ! isnull( mo[2] ) ) model = mo[2];

  if( type == "unknown" && model == "unknown" ) {
    req = http_get( port:port, item:"/css/default/images/kopfbalken_mitte.gif" );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( ! isnull( res  ) ) {
      md5 = hexstr( MD5( res ) );
      if( fingerprint[md5] ) {
        tmp = split( fingerprint[md5], sep:';', keep:FALSE );
        type = tmp[0];
        model = tmp[1];
      }
    }
  }


  set_kb_item( name:"avm_fritz_box/http/" + port + "/type", value:type );
  set_kb_item( name:"avm_fritz_box/http/" + port + "/model", value:model );
  set_kb_item( name:"avm_fritz_box/http/" + port + "/firmware_version", value:fw_version );
}

exit( 0 );
