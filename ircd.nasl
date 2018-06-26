###############################################################################
# OpenVAS Vulnerability Test
# $Id: ircd.nasl 10317 2018-06-25 14:09:46Z cfischer $
#
# IRC daemon identification
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11156");
  script_version("$Revision: 10317 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 16:09:46 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IRC daemon identification");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports("Services/irc", 6667);

  script_tag(name:"summary", value:"This script determines the version of the IRC daemon.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item( "Services/irc" );
if( ! port ) port = 6667;
if( ! get_port_state( port ) ) exit( 0 );

host = get_host_name();

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

nick = NULL;
for( i = 0; i < 9; i++ ) nick += raw_string( 0x41 + ( rand() % 10 ) );

user = nick;

req = string( "NICK ", nick, "\r\n",
              "USER ", nick, " ", this_host_name(), " ", host,
              " :", user, "\r\n" );
send( socket:soc, data:req );

while( a = recv_line( socket:soc, length:4096 ) ) {
  if( a =~ "^PING." ) {
    a = ereg_replace( pattern:"PING", replace:"PONG", string:a );
    send( socket:soc, data:a );
  } else if( a =~ "^ERROR :Closing Link" ) {
    close( soc );
    set_kb_item( name:"ircd/detected", value:TRUE );
    log_message( port:port, data:'Unable to get the version of this service due to the error:\n\n' + a );
    register_service( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );
    exit( 0 );
  }
}

send( socket:soc, data:string( "VERSION\r\n" ) );
v = "x";
while( ( v ) && ! ( " 351 " >< v ) ) v = recv_line( socket:soc, length:256 );
send( socket:soc, data:string( "QUIT\r\n" ) );
close( soc );

if( ! v ) exit( 0 );

register_service( port:port, proto:"irc", message:"An IRC server seems to be running on this port." );
set_kb_item( name:"irc/banner/" + port, value:v );
set_kb_item( name:"ircd/detected", value:TRUE );
set_kb_item( name:"ircd/banner", value:TRUE );

# Answer looks like:
# :irc.sysdoor.com 351 nessus123 2.8/csircd-1.13. irc.sysdoor.com :http://www.codestud.com/ircd
v2 = ereg_replace( string:v, pattern:": *[^ ]+ +[0-9]+ +[a-zA-Z0-9]+ +([^ ]+) +[^ ]+ *:(.*)", replace:"\1 \2" );
if( v == v2 ) exit( 0 );

log_message( port:port, data:"The IRC server version is : " + v2 );
exit( 0 );
