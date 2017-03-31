###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_check_mk_agent_detect.nasl 4747 2016-12-12 14:10:26Z mime $
#
# Check_MK Agent Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.140096");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 4747 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-12 15:10:26 +0100 (Mon, 12 Dec 2016) $");
 script_tag(name:"creation_date", value:"2016-12-12 12:33:00 +0100 (Mon, 12 Dec 2016)");
 script_name("Check_MK Agent Detection");

 script_tag(name: "summary" , value: "This script performs detection of check_mk agent.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown");
 exit(0);
}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( nodefault:TRUE );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

buf = recv( socket:soc, length:512 );

if( "<<<check_mk>>>" >!< buf ) exit( 0 );

set_kb_item( name:"check_mk/agent/installed", value:TRUE );
vers = 'unknown';

register_service( port:port, proto:"check_mk_agent" );

av = eregmatch( pattern:'Version: ([0-9.]+[^ \r\n]+)', string:buf );

if( ! isnull( av[1] ) )
{
  set_kb_item( name:"check_mk/agent/version", value:av[1] );
  vers = av[1];
}

report = build_detection_report( app:"Check_MK Agent", version:vers, install:port +'/TCP' );
log_message( port:port, data:report );

exit( 0 );

