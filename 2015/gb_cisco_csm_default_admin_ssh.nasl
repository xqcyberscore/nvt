###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Appliance Admin SSH Default Credentials
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
  script_oid("1.3.6.1.4.1.25623.1.0.105434");
  script_version("2019-09-02T07:13:48+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Cisco Appliance Admin SSH Default Credentials");
  script_tag(name:"last_modification", value:"2019-09-02 07:13:48 +0000 (Mon, 02 Sep 2019)");
  script_tag(name:"creation_date", value:"2015-11-06 13:18:30 +0100 (Fri, 06 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Cisco Appliance is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default SSH credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/ironport.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("ssh_func.inc");

# If optimize_test = no
if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

port = get_ssh_port( default:22 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

user = 'admin';
pass = 'ironport';

login = ssh_login( socket:soc, login:user, password:pass, pub:FALSE, priv:FALSE, passphrase:FALSE );
if( login == 0 )
{
  cmd = "version";
  res = ssh_cmd( socket:soc, cmd:cmd, nosh:TRUE );
  close( soc );

  if( res =~ '(Email|Web|Content) Security( Virtual)? (Appliance|Management)' )
  {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '" and to execute the "' + cmd + '" command. Result:\n\n' + res;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( soc ) close( soc );
exit( 99 );