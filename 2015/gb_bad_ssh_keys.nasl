###############################################################################
# OpenVAS Vulnerability Test
#
# Static SSH Key Used
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105398");
  script_version("2019-09-02T07:13:48+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Static SSH Key Used");
  script_tag(name:"last_modification", value:"2019-09-02 07:13:48 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"creation_date", value:"2015-10-14 11:48:40 +0200 (Wed, 14 Oct 2015)");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to gain unauthorized access to affected devices. Successfully exploiting this issue allows
  attackers to completely compromise the devices.");

  script_tag(name:"vuldetect", value:"Try to login as root using a known static SSH private key.");

  script_tag(name:"solution", value:"Remove the known SSH private key.");

  script_tag(name:"summary", value:"The remote host has a known private key installed.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("bad_ssh_keys.inc");
include("ssh_func.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

port = get_ssh_port( default:22 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

loginCheck = ssh_login( socket:soc, login:"root", password:NULL, pub:NULL, priv:check_key, passphrase:NULL );
close( soc );

if( loginCheck == 0 )
  exit( 0 ); # unused key accepted. stop test to avoid false positives

foreach entry ( bad_keys )
{
  es = split( entry, sep:":split:", keep:FALSE );
  if( isnull( es[0] ) || isnull( es[1] ) )
    continue;

  user = es[0];
  pkey = es[1];

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  login = ssh_login( socket:soc, login:user, password:NULL, pub:NULL, priv:pkey, passphrase:NULL );
  close( soc );

  if( login == 0 )
  {
    report = 'It was possible to login using username "' + user + '" and the following private ssh key:\n' + pkey + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );