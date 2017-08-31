###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_detect.nasl 6820 2017-07-31 11:37:34Z cfischer $
#
# ZABBIX Server Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100403");
  script_version("$Revision: 6820 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-31 13:37:34 +0200 (Mon, 31 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("ZABBIX Server Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service4.nasl");
  script_require_ports("Services/zabbix_server", 10051);

  script_tag(name:"summary", value:"Detection of ZABBIX Server.

  The script sends a connection request to the server and attempts to
  identify the service from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

# https://www.zabbix.org/wiki/Docs/protocols/zabbix_agent/2.0#Active_agents
reqs = make_list( "ZBX_GET_HISTORY_LAST_ID", # Old agent request
                  '{"request":"active checks","host":"' + get_host_name() + '"}' ); # Zabbix is not responding on the above request on newer versions

port = get_kb_item( "Services/zabbix_server" );
if( ! port ) port = 10051;
if( ! get_port_state( port ) ) exit( 0 );

foreach req( reqs ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  send( socket:soc, data:req );

  buf = recv( socket:soc, length:1024 );
  close( soc );
  if( isnull( buf ) ) continue;

  if( "ZBXD" >< buf ) {
  
    register_service( port:port, proto:"zabbix_server" );
    replace_kb_item( name:"Zabbix/installed", value:TRUE );

    cpe = "cpe:/a:zabbix:zabbix";

    register_product( cpe:cpe, location:port +'/tcp', port:port );

    log_message( data:build_detection_report( app:"Zabbix Server",
                                              version:"unknown",
                                              install:port + "/tcp",
                                              cpe:cpe,
                                              concluded:buf ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
