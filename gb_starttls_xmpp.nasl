###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_starttls_xmpp.nasl 4682 2016-12-06 08:14:23Z cfi $
#
# XMPP STARTTLS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105014");
  script_version("$Revision: 4682 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-06 09:14:23 +0100 (Tue, 06 Dec 2016) $");
  script_tag(name:"creation_date", value:"2014-04-25 12:19:02 +0100 (Fri, 25 Apr 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("XMPP STARTTLS Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("xmpp_detect.nasl");
  script_require_ports("Services/xmpp-client", 5222, "Services/xmpp-server", 5269);
  script_mandatory_keys("xmpp/installed");

  script_tag(name:"summary", value:"The remote XMPP Server supports STARTTLS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

host = get_host_name();

ports = get_kb_list( "Services/xmpp-server" );
if( ! ports ) ports = make_list( 5269 );

foreach port( ports ) {

  if( get_port_state( port ) ) {

    soc = open_sock_tcp( port );
    if( soc ) {

      req = "<stream:stream xmlns='jabber:server' " +
            "xmlns:stream='http://etherx.jabber.org/streams' " +
            "version='1.0' " +
            "to='" + host  + "'>";

      send( socket:soc, data:req );
      recv = recv( socket:soc, length:512 );

      if( "stream:error" >!< recv ) {
        req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
        send( socket:soc, data:req );
        recv = recv( socket:soc, length:256 );

        close( soc );

        if( "<proceed" >< recv ) {
          set_kb_item( name:"xmpp-server/" + port + "/starttls", value:TRUE );
          set_kb_item( name:"starttls_typ/" + port, value:"xmpp-server" );
          log_message( port:port, data:"The remote XMPP server-to-server service is supporting STARTTLS" );
        }
      } else {
        close( soc );
      }
    }
  }
}

port = get_kb_item( "Services/xmpp-client" );
if( ! port ) port = 5222;

if( ! get_tcp_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = "<stream:stream xmlns='jabber:client' " +
      "xmlns:stream='http://etherx.jabber.org/streams' " +
      "version='1.0' " +
      "to='" + host  + "'>";

send( socket:soc, data:req );
recv = recv( socket:soc, length:512 );

if( "stream:error" >< recv ) {
  close( soc );
  exit( 0 );
}

req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
send( socket:soc, data:req );
recv = recv( socket:soc, length:256 );

close( soc );

if( "<proceed" >< recv ) {
  set_kb_item( name:"xmpp-client/" + port + "/starttls", value:TRUE );
  set_kb_item( name:"starttls_typ/" + port, value:"xmpp-client" );
  log_message( port:port, data:"The remote XMPP client-to-server service is supporting STARTTLS" );
}

exit( 0 );
