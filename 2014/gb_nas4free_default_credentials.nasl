###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nas4free_default_credentials.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# nas4free Default Admin Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

tag_summary = 'The remote nas4free web interface is prone to a default
account authentication bypass vulnerability.';

tag_impact = 'This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.';

tag_insight = 'It was possible to login with default credentials.';
tag_vuldetect = 'Try to login with default credentials.';
tag_solution = 'Change the password.';


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105055"); 
 script_version("$Revision: 6692 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("nas4free Default Admin Credentials");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-07-02 12:02:06 +0200 (Wed, 02 Jul 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_nas4free_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("nas4free/installed");

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);

 exit(0);
}

CPE = 'cpe:/a:nas4free:nas4free';

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = '/login.php';
postData = 'username=admin&password=nas4free';
host = get_host_name();

len = strlen( postData );

req = 'POST /login.php HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept-Encoding: identity\r\n' + 
      'Referer: http://' + host + '/login.php' + '\r\n' + 
      'Content-Type: application/x-www-form-urlencoded\r\n' + 
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      postData;

result = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( result =~ "HTTP/1.1 302" && "index.php" >< result )
{
  co = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string: result );
  if( isnull( co[1] ) ) exit( 99 );

  req = 'GET /index.php HTTP/1.1\r\n' + 
        'Host: ' + host + '\r\n' + 
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Cookie: ' + co[1] + '\r\n\r\n';

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "system.php" >< buf && "logout.php" >< buf )
  {
    report = 'It was possible to login with user "admin" and password "nas4free".';
    security_message( port:port, data:report );
    exit( 0 );
  }  

}

exit( 99 );
