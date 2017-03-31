###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpver.nasl 4840 2016-12-22 13:02:22Z cfi $
#
# Detection of HTTP-Version 
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100034");
  script_version("$Revision: 4840 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-22 14:02:22 +0100 (Thu, 22 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTTP-Version Detection");  
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  # nb: Don't add a dependency to http_version.nasl to avoid cyclic dependency to embedded_web_server_detect.nasl
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Check the HTTP-Version");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

soc = http_open_socket( port );
if( ! soc ) exit( 0 );

host = http_host_name( port:port );

req = string( "GET / HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\n",
              "Accept: */*\r\n",
              "Connection: close\r\n",
              "\r\n" ); 
send( socket:soc, data:req );
buf = http_recv_headers2( socket:soc );
close( soc );
if( buf == NULL ) exit( 0 );

if( buf =~ "HTTP/1.1 20[0-6]" || buf =~ "HTTP/1.1 30[0-7]" || buf =~ "HTTP/1.1 40[13]" ) {
  set_kb_item( name:"http/" + port, value:"11" );
  exit( 0 );
}

else if( buf =~ "HTTP/1.0 20[0-6]" || buf =~ "HTTP/1.0 30[0-7]" || buf =~ "HTTP/1.0 40[13]" ) {
  set_kb_item( name:"http/" + port, value:"10" );
  exit( 0 );
}

else if( buf =~ "HTTP/1\.[0-1] 50[0-4]" ) {
  set_kb_item( name:"Services/www/" + port + "/broken/", value:TRUE );
  set_kb_item( name:"Services/www/" + port + "/broken/reason", value:"50x" );
  exit( 0 );
}

else {

  soc = http_open_socket( port );
  if( ! soc ) exit( 0 );
  req = string( "GET / HTTP/1.0\r\n",
                "\r\n" );
  send( socket:soc, data:req );
  buf = http_recv_headers2( socket:soc );
  if( buf == NULL ) exit( 0 );
  close( soc );

  if( buf =~ "HTTP/1.0 20[0-6]" || buf =~ "HTTP/1.0 30[0-7]" || buf =~ "HTTP/1.0 40[13]") {
    set_kb_item( name:"http/" + port, value:"10" );
    exit( 0 );
  } else if( buf =~ "HTTP/1\.[0-1] 50[0-9]" ) {
    set_kb_item( name:"Services/www/" + port + "/broken/", value:TRUE );
    set_kb_item( name:"Services/www/" + port + "/broken/reason", value:"50x" );
    exit( 0 );
  }
} 

## if all fail set to 1.0 anyway
set_kb_item( name:"http/" + port, value:"10" );

exit( 0 );
