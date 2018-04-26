###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssh_login_failed.nasl 9612 2018-04-25 14:40:10Z cfischer $
#
# SSH Login Failed For Authenticated Checks
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105936");
  script_version("$Revision: 9612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 16:40:10 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-12-16 10:58:24 +0700 (Tue, 16 Dec 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Login Failed For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ssh_authorization.nasl", "gb_ssh_algos.nasl");
  script_mandatory_keys("login/SSH/failed");

  script_tag(name:"summary", value:"It was NOT possible to login using the provided SSH
  credentials. Hence authenticated checks are not enabled.");

  script_tag(name:"solution", value:"Recheck the SSH credentials for authenticated checks.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

libssh_supported = make_array();
host_supported   = make_array();
host_unsupported = make_array();

# The types we want to check defined in gb_ssh_algos.ssh
check_types = make_list(
"kex_algorithms",
"server_host_key_algorithms",
"encryption_algorithms_server_to_client",
"mac_algorithms_server_to_client",
"compression_algorithms_server_to_client" );

# The list of features libssh is currently supporting.
# See https://www.libssh.org/features/
libssh_supported['kex_algorithms'] = make_list(
"curve25519-sha256@libssh.org", # Available in libssh >= 0.7.0
"ecdh-sha2-nistp256",
"diffie-hellman-group1-sha1",
"diffie-hellman-group14-sha1" );

libssh_supported['server_host_key_algorithms'] = make_list(
"ssh-ed25519", # Available in libssh >= 0.7.0
"ecdsa-sha2-nistp256",
"ecdsa-sha2-nistp384",
"ecdsa-sha2-nistp521",
"ssh-dss",
"ssh-rsa" );

libssh_supported['encryption_algorithms_server_to_client'] = make_list(
"aes256-ctr",
"aes192-ctr",
"aes128-ctr",
"aes256-cbc",
"aes192-cbc",
"aes128-cbc",
"3des-cbc",
"blowfish-cbc"
);

libssh_supported['mac_algorithms_server_to_client'] = make_list(
"hmac-sha2-512",
"hmac-sha2-256",
"hmac-sha1",
"none"
);

libssh_supported['compression_algorithms_server_to_client'] = make_list(
"zlib@openssh.com",
"zlib",
"none"
);

port = get_preference( "auth_port_ssh" );
if( ! port )
  port = get_kb_item( "Services/ssh" );

if( get_kb_item( "ssh/" + port + "/algos_available" ) ) {

  foreach check_type( check_types ) {

    host_list = get_kb_list( "ssh/" + port + "/" + check_type );

    if( host_list ) {

      host_unsupported[check_type] = make_list();
      host_supported[check_type]   = make_list( host_list );

      foreach single_item( host_list ) {
        if( ! in_array( search:single_item, array:libssh_supported[check_type] ) ) {
          host_unsupported[check_type] = make_list( host_unsupported[check_type], single_item );
        }
      }
    }
  }
}

foreach check_type( check_types ) {

  host_supported_items   = max_index( host_supported[check_type] );
  host_unsupported_items = max_index( host_unsupported[check_type] );

  if( host_supported_items <= host_unsupported_items && host_unsupported_items > 0 ) {
    tmp_report += 'Current supported ' + check_type + ' of the scanner:\n';
    tmp_report += join( list:sort( libssh_supported[check_type] ), sep:"," ) + '\n\n';
    tmp_report += 'Current supported ' + check_type + ' of the remote host:\n';
    tmp_report += join( list:sort( host_supported[check_type] ), sep:"," ) + '\n\n';
  }
}

if( tmp_report ) {
  tmp_report = ereg_replace( pattern:"(ssh-ed25519|curve25519-sha256@libssh\.org)", string:tmp_report, replace:"\1 (requires libssh >= 0.7.0 on the scanner)" );
  report  = "If the SSH credentials are correct the login might have failed because the ";
  report += "SSH server isn't supporting one of the following algorithms currently required:";
  report += '\n\n' + tmp_report;
}

log_message( port:port, data:report );
exit( 0 );
