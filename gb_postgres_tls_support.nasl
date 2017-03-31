###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgres_tls_support.nasl 4682 2016-12-06 08:14:23Z cfi $
#
# PostgreSQL TLS Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105013");
  script_version("$Revision: 4682 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 09:14:23 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2014-04-25 11:29:22 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("PostgreSQL TLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed");

  script_tag(name:"summary", value:"The remote PostgreSQL Server supports TLS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/postgresql" );
if( ! port ) port = 5432;
if( ! get_tcp_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = raw_string( 0x00, 0x00, 0x00, 0x08,
                  0x04, 0xD2, 0x16, 0x2F );

send( socket:soc, data:req );
recv = recv( socket:soc, length:1 );

close( soc );

if( recv == "S" ) {
  set_kb_item( name:"postgres/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"postgres" );
  log_message( port:port );
}

exit( 0 );
