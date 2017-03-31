###############################################################################
# OpenVAS Vulnerability Test
# $Id: xtux_server.nasl 4372 2016-10-27 14:29:58Z cfi $
#
# xtux server detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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

# xtux server will start looping and eat CPU if it receives bad input.
# Writing a nice plugin is useless, as xtux is killed by find_service!
#
# See Bugtraq :
# From:"b0iler _" <b0iler@hotmail.com>
# Subject: xtux server DoS.
# Date: Sat, 09 Mar 2002 15:53:32 -0700
#
# nb: Fixed according to https://sourceforge.net/p/xtux/bugs/9/#249b

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11016");
  script_version("$Revision: 4372 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-27 16:29:58 +0200 (Thu, 27 Oct 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("xtux server detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_require_ports(8390);
  script_dependencies("find_service.nasl");

  tag_summary = "The xtux server might be running on this port. If somebody connects to
  it and sends it garbage data, it may loop and overload your CPU.";

  tag_solution = "Disable it, or at least firewall it";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

port = 8390;
kb = known_service( port:port );
if( kb && kb != "xtux" ) exit( 0 );

if( get_port_state( port ) ) {

  soc = open_sock_tcp(port);
  if( soc ) {
    log_message( port:port );
    close( soc );
  }
}

exit( 0 );