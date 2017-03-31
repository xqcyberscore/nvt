###############################################################################
# OpenVAS Vulnerability Test
# $Id: ident_backdoor2.nasl 5274 2017-02-12 13:52:52Z cfi $
#
# IRC bot detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# I'm not sure what this backdoor is...

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18392");
  script_version("$Revision: 5274 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-12 14:52:52 +0100 (Sun, 12 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IRC bot detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Malware");
  script_require_ports("Services/fake-identd", 113);
  script_dependencies("find_service1.nasl");

  tag_summary = "This host seems to be running an ident server, but before any 
  request is sent, the server gives an answer about a connection to port 6667.";

  tag_insight = "It is very likely this system has heen compromised by an IRC 
  bot and is now a 'zombi' that can participate into 'distributed 
  denial of service' (DDoS).";

  tag_solution = "Desinfect or re-install your system";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

regex = '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+';

port = get_kb_item( 'Services/fake-identd' );
if( ! port ) port = 113;
if( ! get_port_state( port ) ) exit( 0 );

b = get_kb_item( "FindService/tcp/" + port + "/spontaneous" );
if( ! b ) exit( 0 );

if( b =~ '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+' ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );