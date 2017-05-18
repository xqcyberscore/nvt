###############################################################################
# OpenVAS Vulnerability Test
# $Id: default_ssh_credentials.nasl 5990 2017-04-20 13:39:40Z cfi $
#
# SSH Brute Force Logins With Default Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108013");
  script_version("$Revision: 5990 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-20 15:39:40 +0200 (Thu, 20 Apr 2017) $");
  script_tag(name:"creation_date", value:"2011-09-06 14:38:09 +0200 (Tue, 06 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Brute Force Logins With Default Credentials");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_add_preference(name:"Seconds to wait between probes", value:"", type:"entry");

  script_timeout(900);

  script_tag(name:"summary", value:"A number of known default credentials is tried for log in via SSH protocol.
  As this NVT might run into a timeout the actual reporting of this vulnerability takes place in the
  NVT 'SSH Brute Force Logins with default Credentials Reporting' (OID: 1.3.6.1.4.1.25623.1.0.103239)");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("default_credentials.inc");
include("ssh_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/ssh");
if( ! port ) port = 22;
if( ! get_port_state( port ) ) exit( 0 );

# Exit if any random user/pass pair is accepted by the SSH service.
if( ssh_broken_random_login( port:port ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );
sess_id = ssh_session_id_from_sock( soc );
ssh_supported_authentication = get_ssh_supported_authentication( sess_id:sess_id );
close( soc );

if( ssh_supported_authentication =~ "^publickey$" ) exit( 0 );

c = 0;

d = script_get_preference( "Seconds to wait between probes" );
if( int( d ) > 0 ) delay = int( d );

replace_kb_item( name:"default_ssh_credentials/started", value:TRUE );

foreach credential( credentials ) {

  credential = str_replace( string:credential, find:"\;", replace:"#sem#" );

  user_pass = split( credential, sep:";", keep:FALSE );

  if( isnull( user_pass[0] ) || isnull( user_pass[1] ) ) continue;

  if( ! soc = open_sock_tcp( port ) ) exit( 0 );

  user = chomp( user_pass[0] );
  pass = chomp( user_pass[1] );

  user = str_replace( string:user, find:"#sem#", replace:";" );
  pass = str_replace( string:pass, find:"#sem#", replace:";" );

  if( tolower( pass ) == "none" ) pass = "";

  login = ssh_login( socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL );

  if( login == '-2' ) {
    close( soc );
    exit( 0 ); # "authentication succeeded using the none method". Against such ssh services it makes no sense to continue here
  }

  close( soc );

  if( login == 0 ) {
    c++;
    set_kb_item( name:"default_ssh_credentials/" + port + "/credentials", value:user + ":" + pass );

    if( c >= 10 ) {
      set_kb_item( name:"default_ssh_credentials/" + port + "/too_many_logins", value:c );
      exit( 0 );
    }
  }

  if( delay ) {
    sleep( delay );
  } else {
    usleep( 50000 );
  }
}

# Set kb entry that no timeout was happening for further reporting
set_kb_item( name:"default_ssh_credentials/" + port + "/no_timeout", value:TRUE );

exit( 0 );
