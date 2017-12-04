###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssh_detect.nasl 7902 2017-11-24 11:02:42Z cfischer $
#
# SSH Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10267");
  script_version("$Revision: 7902 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 12:02:42 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_name("SSH Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service2.nasl", "external_svc_ident.nasl");
  script_require_ports("Services/ssh", 22);

  script_tag(name:"summary", value:"This detects the SSH Server's type and version by connecting to the server
  and processing the buffer received.

  This information gives potential attackers additional information about the system they are attacking.
  Versions and Types should be omitted where possible.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("host_details.inc");
include("cpe.inc");

CONNECT_LOGIN  = "VulnScan";
CONNECT_PASSWD = "VulnScan";

sshPort = get_ssh_port( default:22 );

soc = open_sock_tcp( sshPort );
if( ! soc ) exit( 0 );

server_banner = get_ssh_server_banner( port:sshPort );

ssh_login( socket:soc, login:CONNECT_LOGIN, password:CONNECT_PASSWD,
           pub:NULL, priv:NULL, passphrase:NULL );

sess_id      = ssh_session_id_from_sock( soc );
login_banner = get_ssh_banner( sess_id:sess_id );
supported    = get_ssh_supported_authentication( sess_id:sess_id );
close( soc );

if( server_banner ) {

  text = 'Remote SSH server version: ' + server_banner + '\n';

  text += 'Remote SSH supported authentication: ';
  if( supported ) {
    set_kb_item( name:"SSH/supportedauth/" + sshPort, value:supported );
    text += supported + '\n';
  } else {
    text += '(not available)\n';
  }

  text += 'Remote SSH banner: ';
  if( login_banner ) {
    set_kb_item( name:"SSH/textbanner/" + sshPort, value:login_banner );
    text += '\n' + login_banner + '\n\n';
  } else {
    text += '(not available)\n\n';
  }

  # TODO: Move into own detection NVT
  if( "OpenSSH" >< server_banner ) {
    ## build cpe and store it as host_detail
    cpe = build_cpe( value:server_banner, exp:"OpenSSH[_ ]([.a-zA-Z0-9]*)[- ]?.*", base:"cpe:/a:openbsd:openssh:");
    set_kb_item( name:"openssh/detected", value:TRUE );
    if( isnull( cpe ) )
      cpe = "cpe:/a:openbsd:openssh";
    register_product( cpe:cpe, location:sshPort + "/tcp", port:sshPort );
  }

  if( cpe ) text += 'CPE: ' + cpe;
  text += '\n\nConcluded from remote connection attempt with credentials:';
  text += '\n  Login: ' + CONNECT_LOGIN;
  text += '\n  Password: ' + CONNECT_PASSWD;
  text += '\n';

  register_service( port: sshPort, proto:"ssh", message:text );
  log_message( port:sshPort, data:text );
}

exit( 0 );