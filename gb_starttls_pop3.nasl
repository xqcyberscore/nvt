###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_pop3.nasl 4683 2016-12-06 08:45:07Z cfi $
#
# POP3 STARTTLS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105008");
  script_version("$Revision: 4683 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 09:45:07 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2014-04-09 16:29:22 +0100 (Wed, 09 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("POP3 STARTTLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/pop3", 110);

  script_tag(name:"summary", value:"The remote POP3 Server supports the STARTTLS command.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("pop3_func.inc");

port = get_pop3_port( default:110 );

if( get_port_transport( port ) > ENCAPS_IP ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

banner = recv_line( socket:soc, length:2048 );
if( ! banner ) exit( 0 );

send( socket:soc, data:'STLS\r\n' );
while( buf = recv_line( socket:soc, length:2048 ) ) {

  if( eregmatch( pattern:'^\\+OK', string:buf ) ) {
    set_kb_item( name:"pop3/" + port + "/starttls", value:TRUE );
    set_kb_item( name:"starttls_typ/" + port, value:"pop3" );
    log_message( port:port );
    close( soc );
    exit( 0 );
  }
}

exit( 0 );
