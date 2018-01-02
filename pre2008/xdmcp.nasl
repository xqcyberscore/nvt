###############################################################################
# OpenVAS Vulnerability Test
# $Id: xdmcp.nasl 8236 2017-12-22 10:28:23Z cfischer $
#
# X Display Manager Control Protocol (XDMCP)
#
# Authors:
# Pasi Eronen <pasi.eronen@nixu.com>
#
# Copyright:
# Copyright (C) 2002 Pasi Eronen
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
  script_oid("1.3.6.1.4.1.25623.1.0.10891");
  script_version("$Revision: 8236 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 11:28:23 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("X Display Manager Control Protocol (XDMCP) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Pasi Eronen");
  script_family("Service detection");
  script_require_udp_ports(177);

  tag_solution = "XDMCP should either be disabled or limited in the machines which
  may access the service. ";

  tag_summary = "The XDMCP service is running on the remote host";

  tag_insight = "The login and password for XDMCP is transmitted in plaintext.
  This makes the system vulnerable to Man-in-the-middle attacks, making it easy
  for an attacker to steal the credentials of a legitimate user by impersonating
  the XDMCP server. In addition to this, since XDMCP is not a ciphered protocol,
  an attacker has an easier time capturing the keystrokes entered by the user. ";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

# this magic info request packet
req = raw_string( 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00 );

port = 177;

if( ! get_udp_port_state( port ) ) exit( 0 );

soc = open_sock_udp( port );

if( soc ) {

  send( socket:soc, data:req );
  result = recv(socket:soc, length:1000);
  close( soc );
  if( result && ( result[0] == raw_string( 0x00 ) ) &&
                ( result[1] == raw_string( 0x01 ) ) &&
                ( result[2] == raw_string(0x00 ) ) ) {
    log_message( port:port, protocol:"udp" );
    exit( 0 );
  }
}

exit( 0 );