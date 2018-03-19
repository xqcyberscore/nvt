###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gsa_admin_login.nasl 9128 2018-03-19 07:45:38Z cfischer $
#
# GSA Default Admin Credentials
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:greenbone:greenbone_security_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105354");
  script_version("$Revision: 9128 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("GSA Default Admin Credentials");
  script_tag(name:"last_modification", value:"$Date: 2018-03-19 08:45:38 +0100 (Mon, 19 Mar 2018) $");
  script_tag(name:"creation_date", value:"2015-09-14 14:47:11 +0200 (Mon, 14 Sep 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_require_ports("Services/www", 80, 443, 9392);
  script_dependencies("gb_gsa_detect.nasl");
  script_mandatory_keys("gsa/installed");

  script_tag(name:"summary", value:"The remote GSA is prone to a default account authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/admin, sadmin/changeme or admin/openvas");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/omp";

creds = make_array( "admin",  "admin", # OpenVAS Virtual Appliance
                    "sadmin", "changeme", # Docker image from https://github.com/falegk/openvas_pg#usage
                    "admin",  "openvas" ); # Docker image from https://github.com/mikesplain/openvas-docker#usage

host   = http_host_name( port:port );
vuln   = FALSE;
report = "It was possible to login using the following credentials:";

foreach cred( keys( creds ) ) {

  bound = rand();

  post_data = '-----------------------------' + bound + '\r\n' +
              'Content-Disposition: form-data; name="cmd"\r\n' +
              '\r\n' +
              'login\r\n' +
              '-----------------------------' + bound + '\r\n' +
              'Content-Disposition: form-data; name="text"\r\n' +
              '\r\n' +
              '/omp?r=1\r\n' +
              '-----------------------------' + bound + '\r\n' +
              'Content-Disposition: form-data; name="login"\r\n' +
              '\r\n' +
              cred + '\r\n' +
              '-----------------------------' + bound + '\r\n' +
              'Content-Disposition: form-data; name="password"\r\n' +
              '\r\n' +
              creds[cred] + '\r\n' +
              '-----------------------------' + bound + '--\r\n';

  len = strlen( post_data );

  req = 'POST ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: de,en-US;q=0.7,en;q=0.3\r\n' +
        'Accept-Encoding: identity\r\n' +
        'Referer: http://' + host + '/login/login.html\r\n' +
        'Connection: close\r\n' +
        'Content-Type: multipart/form-data; boundary=---------------------------' + bound + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        post_data;
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "HTTP/1.1 303" >!< buf ) continue;

  token = eregmatch( pattern:'token=([^\r\n "]+)', string:buf );
  if( isnull( token[1] ) ) continue;

  cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
  if( isnull( cookie[1] ) ) continue;

  url += '?r=1&token=' + token[1];

  if( http_vuln_check( port:port, url:url, pattern:">Logged in as<", extra_check:make_list( ">Tasks<", ">Targets<", ">Logout<" ), cookie:cookie[1] ) ) {
    vuln = TRUE;
    report += '\n\n' + cred + ":" + creds[cred] + '\n';
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
