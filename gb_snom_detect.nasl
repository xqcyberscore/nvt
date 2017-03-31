###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_snom_detect.nasl 4893 2016-12-30 15:49:57Z cfi $
#
# Snom Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105168");
  script_version("$Revision: 4893 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-30 16:49:57 +0100 (Fri, 30 Dec 2016) $");
  script_tag(name:"creation_date", value:"2015-01-14 11:10:30 +0100 (Wed, 14 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Snom Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl", "find_service.nasl");
  script_mandatory_keys("sip/detected");

  script_tag(name:"summary", value:"The script sends a connection
  request to the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("sip.inc");

infos = get_sip_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = get_sip_banner( port:port, proto:proto );
if( ! banner || "snom" >!< banner ) exit( 0 );

model = 'Unknown Model';
version = 'unknown';
cpe = 'cpe:/h:snom';

set_kb_item( name:"snom/installed", value:TRUE );

model_version = eregmatch( pattern:'snom([0-9]*)/([^\r\n]+)', string:banner );

if( ! isnull( model_version[1] ) && model_version[1] != "" ) {
  model = model_version[1];
  cpe += ':snom_' + model;
  set_kb_item( name:"snom/model", value:model );
} else {
  cpe += ':snom_unknown_model';
}

if( ! isnull( model_version[2] ) ) {
  version = model_version[2];
  cpe += ':' + version;
  set_kb_item( name:"snom/version", value:version );
}

location = port + "/" + proto;

register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );

log_message( data:build_detection_report( app:"Snom " + model,
                                          version:version,
                                          install:location,
                                          cpe:cpe,
                                          concluded:banner ),
                                          port:port,
                                          proto:proto );

exit( 0 );
