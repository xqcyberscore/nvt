###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mobotix_cameras_default_credentials.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Mobotix Cameras Default Admin Credentials
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

tag_summary = 'The remote Mobotix camera web interface is prone to a default
account authentication bypass vulnerability.';

tag_impact = 'This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.';

tag_insight = 'It was possible to login with default credentials admin/meinsm.';
tag_vuldetect = 'Try to login with default credentials.';
tag_solution = 'Change the password.';


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105060"); 
 script_version("$Revision: 6715 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mobotix Cameras Default Admin Credentials");
 script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-07-15 10:02:06 +0200 (Tue, 15 Jul 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);

 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);

 exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! get_port_state( port ) ) exit( 0 );

host = get_host_name();
url = '/admin/index.html';

req = 'GET ' + url + ' HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n';

buf = http_send_recv( port:port, data:req + '\r\n', bodyonly:FALSE );
if( "401 Unauthorized" >!< buf || "MOBOTIX Camera User" >!< buf ) exit( 0 );

userpass64 = base64( str:'admin:meinsm' );

req += 'Authorization: Basic ' + userpass64 + '\r\n\r\n';
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 200" && "/admin/access" >< buf )
{
  report = 'It was possible to login with username "admin" and password "meinsm"\n';
  security_message( port:port, data:report);
} 

exit( 99 );

