###############################################################################
# OpenVAS Vulnerability Test
#
# CAREL pCOWeb Default Account Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103716");
  script_version("2019-06-06T07:39:31+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("CAREL pCOWeb Default Account Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121716/CAREL-pCOWeb-1.5.0-Default-Credential-Shell-Access.html");
  script_tag(name:"last_modification", value:"2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2013-05-23 11:24:55 +0200 (Thu, 23 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/carel/pcoweb/detected");

  script_tag(name:"summary", value:"The remote pCOWeb is prone to a default account authentication bypass
  vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to
  gain access to sensitive information or modify system configuration.

  It was possible to login as user 'http' with no password.");

  script_tag(name:"solution", value:"Login with telnet and set a password or change the shell from '/bin/bash' to '/bin/nologin'.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = telnet_get_port(default:23);
banner = telnet_get_banner(port:port);
if(!banner || "pCOWeb login" >!< banner )
  exit( 0 );

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

buf = telnet_negotiate(socket:soc);
if("pCOWeb login" >!< buf) {
  close(soc);
  exit(0);
}

send(socket:soc, data:'http\r\n');
recv = recv(socket:soc, length:4096);

if(recv !~ "\[http@pCOWeb.*/\]\$") {
  close(soc);
  exit(0);
}

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  send(socket:soc, data:'cat /' + file + '\r\n');
  recv = recv(socket:soc, length:8192);

  if(egrep(string:recv, pattern:pattern)) {
    security_message(data:"The target was found to be vulnerable.", port:port);
    exit(0);
  }
}

exit(99);