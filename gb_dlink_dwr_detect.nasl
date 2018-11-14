###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dwr_detect.nasl 12336 2018-11-13 13:56:12Z jschulte $
#
# D-Link DWR Devices Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113293");
  script_version("$Revision: 12336 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-13 14:56:12 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-08 16:44:00 +0100 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("D-Link DWR Devices Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Detects whether the target is a D-Link DWR Router
  and if so, tries to figure out the model number and installed firmware version.");

  script_xref(name:"URL", value:"https://dlink.com");

  exit(0);
}

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

url = '/EXCU_SHELL';

add_headers = make_array( 'cmdnum', '1', 'command1', 'wrt -x get wrt.system.version', 'confirm1', 'n' );
req = http_get_req( port: port, url: url, add_headers: add_headers, accept_header: '*/*', host_header_use_ip: TRUE );
res = http_keepalive_send_recv( port: port, data: req );

infos = "";
model = "";
info = eregmatch( string: res, pattern: 'value="([^"]+)"', icase: TRUE );
if( ! isnull( info[1] ) ) {

  infos = info[1];

  mod = eregmatch( string: infos, pattern: '(DWR-[0-9]+)', icase: TRUE );
  if( isnull( mod[1] ) ) exit( 0 );
  model = mod[1];
}
else {
  res = http_get_cache( port: port, item: "/js/func.js" );
  mod = eregmatch( string: res, pattern: 'model_name="(DWR-[0-9]+)"', icase: TRUE);
  if( isnull( mod[1] ) ) exit( 0 );
  model = mod[1];
  infos = mod[0];
}

set_kb_item( name: "Host/is_dlink_device", value: TRUE );
set_kb_item( name: "Host/is_dlink_dwr_device", value: TRUE );

set_kb_item( name: "d-link/dwr/model", value: model );

version = "unknown";

ver = eregmatch( string: infos, pattern: 'FW([0-9.]+)', icase: TRUE );
if( ! isnull( ver[1] ) ) {
  version = ver[1];
  set_kb_item( name: "d-link/dwr/fw_version", value: version );
}

CPE = 'cpe:/h:d-link:' + tolower( model ) + ":";

register_and_report_cpe( app: 'D-Link ' + model,
                         ver: version,
                         concluded: infos,
                         base: CPE,
                         expr: '([0-9.]+)',
                         insloc: '/',
                         regPort: port,
                         conclUrl: url );

exit( 0 );
