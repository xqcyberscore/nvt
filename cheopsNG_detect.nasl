###############################################################################
# OpenVAS Vulnerability Test
# $Id: cheopsNG_detect.nasl 10890 2018-08-10 12:30:06Z cfischer $
#
# Cheops NG Agent Detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.20160");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10890 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:30:06 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Cheops NG Agent Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 2300);

  script_xref(name:"URL", value:"http://cheops-ng.sourceforge.net/");

  script_tag(name:"summary", value:"The remote host is running a network management tool.

Description :

The remote host is running a Cheops NG agent.  Cheops NG is an
open-source network management tool, and the cheops-agent provides a
way for remote hosts to communicate with the tool and use it to map
your network, port scan machines and identify running services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

m1 = '\x00\x00\x00\x14\x00\x0c\x00\x04\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00';
m2 = '\x00\x00\x00\x20\x00\x0c\x00\x02\x00\x00\x00\x00\x01\x00\x00\x7f\x01\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xdf\x0d\x08';

port = get_unknown_port( default:2300 );

soc = open_sock_tcp( port );
if( soc ) {
  send( socket:soc, data:m1 );
  r = recv( socket:soc, length:512 );
  if( strlen( r ) > 0 ) {
    if( debug_level ) debug_print('Service on port ', port, ' answers to first request - L=', strlen(r), '\n');
    if( substr( r, 0, 7 ) == '\x00\x00\x00\x10\x00\x0c\x00\x6c' ) {
      log_message( port:port );
      register_service( port:port, proto:'cheops-ng' );
      set_kb_item( name:'cheopsNG/password', value:port );
    }
    close( soc );
    exit( 0 );
  }
  send( socket:soc, data:m2 );
  r = recv( socket:soc, length:512 );
  l = strlen( r );
  if( debug_level ) debug_print('reply length = ', l, '\n');
  if( l >= 8 && substr( r, 0, 2 ) == '\0\0\0' && '\x01\x00\x00\x7f' >< r ) {
    log_message( port:port );
    register_service( port:port, proto:'cheops-ng' );
    set_kb_item( name:'cheopsNG/unprotected', value:port );
  }
  close( soc );
}

exit( 0 );
