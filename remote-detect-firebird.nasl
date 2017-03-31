# OpenVAS Vulnerability Test
# $Id: remote-detect-firebird.nasl 5499 2017-03-06 13:06:09Z teissa $
# Description: This script ensure that a Firebird/Interbase database server is installed and running
#
# remote-detect-firebird.nasl
#
# Authors:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
# Slight modification by Vlatko Kosturjak - Kost <kost@linux.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80004");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 5499 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-06 14:06:09 +0100 (Mon, 06 Mar 2017) $");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Firebird/Interbase database Server service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");

  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 3050);

  script_tag(name:"solution", value:"It's recommended to allow connection to this host only from trusted hosts or networks,
  or disable the service if not used.");
  script_tag(name:"summary", value:"The remote host is running the Firebird/Interbase database Server. 
  Firebird is a RDBMS offering many ANSI SQL:2003 features. 
  It runs on Linux, Windows, and a variety of Unix platforms 
  and Started as a fork of Borland's open source release of InterBase");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);

}

include("misc_func.inc");
include("host_details.inc");

port = get_unknown_port( default:3050 );

response = "";

# forge the firebird negotiation protocol

firebird_auth_packet   = raw_string(
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x13,0x00,0x00,0x00,0x02,0x00,
0x00,0x00,0x24,0x00,0x00,0x00,0x1c,0x2f,0x6f,0x70,0x74,0x2f,0x66,
0x69,0x72,0x65,0x62,0x69,0x72,0x64,0x2f,0x62,0x69,0x6e,0x2f,0x6c,
0x65,0x67,0x69,0x6f,0x6e,0x2e,0x66,0x64,0x62,0x00,0x00,0x00,0x02,
0x00,0x00,0x00,0x17,0x01,0x04,0x72,0x6f,0x6f,0x74,0x04,0x09,0x63,
0x68,0x72,0x69,0x73,0x74,0x69,0x61,0x6e,0x05,0x04,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x0a,
0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,
0x00,0x00,0x04);
 

# Connect to remote Firebird/Interbase server
soc = open_sock_tcp(port);

if(soc)
{
    send(socket:soc, data:firebird_auth_packet);
    response = recv(socket:soc, length:1024);

    close(soc);

    if(!isnull(response) && strlen(response) == 16 && "030000000a0000000100000003" >< hexstr(response)) {

        set_kb_item( name:"firebird_db/installed", value:TRUE );

        register_service(port:port, ipproto:"tcp", proto:"gds_db");

        cpe = 'cpe:/a:firebirdsql:firebird';

        register_product( cpe:cpe, location:port + '/tcp', port:port );

        log_message( data: build_detection_report( app:"Firebird/Interbase database",
                                                   install:port + '/tcp',
                                                   cpe:cpe),
                                                   port:port);
    }
}

exit(0);