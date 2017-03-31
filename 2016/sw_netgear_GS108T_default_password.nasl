###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_netgear_GS108T_default_password.nasl 5527 2017-03-09 10:00:25Z teissa $
#
# Netgear GS108T Default Password
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105629");
  script_version ("$Revision: 5527 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Netgear GS108T Default Password");
  script_tag(name:"last_modification", value:"$Date: 2017-03-09 11:00:25 +0100 (Thu, 09 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-29 11:25:48 +0200 (Fri, 29 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.netgear.com/support/product/GS108Tv1.aspx");

  script_tag(name:"solution", value:"Change the password.");
  script_tag(name:"summary", value:"The remote Netgear GS108T device has the default password 'password'.");
  script_tag(name:"affected", value:"Netgear GS108T devices. Other models might be also affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

buf = http_get_cache( item:"/", port:port );

if( "<title>NetGear" >!< buf ) exit( 0 );

host = http_host_name( port:port );

data = string( "password=password&rtime=" + unixtime() + ".99" );
len = strlen( data );

req = string( "POST /login.cgi HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "DNT: 1\r\n",
              "Referer: http://", host, "/\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", len, "\r\n",
              "\r\n",
              data );
res = http_keepalive_send_recv( port:port, data:req );

cookie = eregmatch( pattern:"Broadcom-WebSuperSmart=([0-9a-zA-Z]+);", string:res );
if( isnull( cookie[1] ) ) exit( 0 );

req = string( "GET /sysinfo.html HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Cookie: Broadcom-WebSuperSmart=", cookie[1], "\r\n\r\n" );
res = http_keepalive_send_recv( port:port, data:req );

if( "System Information" >< res && "MAC address" >< res ) {
  security_message( port:port, data:"It was possible to login with the default password 'password'" );
  exit( 0 );
}

exit( 99 );
