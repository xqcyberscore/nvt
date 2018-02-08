###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service5.nasl 8704 2018-02-07 14:32:07Z cfischer $
#
# Service Detection with 'SIP' Request
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108203");
  script_version("$Revision: 8704 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-07 15:32:07 +0100 (Wed, 07 Feb 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 09:08:04 +0200 (Fri, 04 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with 'SIP' Request");
  script_category(ACT_GATHER_INFO); 
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service4.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'SIP' OPTIONS
  request to the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("global_settings.inc");
include("sip.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

# nb: The sip functions are defaulting to "udp" if no proto: parameter is passed so setting "tcp" here
proto = "tcp";

soc = open_sip_socket( port:port, proto:proto );
if( ! soc ) exit( 0 );

# This is a request where a Zabbix Server is answering to. There might be other services out there answering to
# such a SIP request so trying this as well for other unknown services.
req = construct_sip_options_req( port:port, proto:proto );
send( socket:soc, data:req );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to a "SIP OPTIONS" request', "\n" );
  exit( 0 );
}

k = "FindService/tcp/" + port + "/sip";
set_kb_item( name:k, value:r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:hexstr( r ) );

if( r =~ "^SIP/2\.0" || r =~ "^Via: SIP/2\.0" ) {
  register_service( port:port, proto:"sip", message:"A service supporting the SIP protocol was idendified." );
  log_message( port:port, data:"A service supporting the SIP protocol was idendified." );
  exit( 0 );
}

# Check_MK Agent, find_service1.nasl should already do the job but sometimes the Agent behaves strange
# and only sends data too late. This is a fallback for such a case.
if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  # Check_MK Agents seems to not answer to repeated requests in a short amount of time so saving the response here for later processing.
  replace_kb_item( name:"check_mk_agent/banner/" + port, value:r );
  register_service( port:port, proto:"check_mk_agent", message:"A Check_MK Agent seems to be running on this port." );
  log_message( port:port, data:"A Check_MK Agent seems to be running on this port." );
  exit( 0 );
}

# 0x00:  70 02 77 61                                        p.wa 
if( hexstr( r ) =~ "^70027761$" ) {
  register_service( port:port, proto:"activemq_mqtt", message:"A ActiveMQ MQTT service seems to be running on this port." );
  log_message( port:port, data:"A ActiveMQ MQTT service seems to be running on this port." );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if( ! r0 ) set_unknown_banner( port:port, banner:r );
