###############################################################################
# OpenVAS Vulnerability Test
#
# mldonkey telnet
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

# Note: this script is not very useful because mldonkey only allows
# connections from localhost by default

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11124");
  script_version("2019-06-06T07:39:31+0000");
  script_tag(name:"last_modification", value:"2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_name("mldonkey telnet");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/mldonkey-telnet", 4000);

  script_tag(name:"solution", value:"Disable it");

  script_tag(name:"summary", value:"mldonkey telnet interface might be running on this port.
  This peer to peer software is used to share files.

  1. This may be illegal.

  2. You may have access to confidential files

  3. It may eat too much bandwidth");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = get_kb_item( "Services/mldonkey-telnet" );
if( ! port ) port = 4000;
if( ! get_port_state( port ) ) exit( 0 );

r = telnet_get_banner( port:port );
if( ! r ) exit( 0 );

if( "Welcome on mldonkey command-line" >< r ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );