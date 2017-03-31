###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apache_axis2_services_detect.nasl 3690 2016-07-12 18:36:57Z cfi $
#
# Apache Axis2 Web Services Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:apache:axis2';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.111008");
 script_version("$Revision: 3690 $");
 script_tag(name:"last_modification", value:"$Date: 2016-07-12 20:36:57 +0200 (Tue, 12 Jul 2016) $");
 script_tag(name:"creation_date", value:"2015-03-20 08:00:00 +0100 (Fri, 20 Mar 2015)");

 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("Apache Axis2 Web Services Detection");

 script_summary("Checks for the presence of Apache Axis2 Web Services");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
 script_dependencies("gb_apache_axis2_detect.nasl");
 script_require_ports("Services/www", 8080,8081);
 script_mandatory_keys("axis2/installed");

 script_tag(name : "summary" , value:"This host is running Apache Axis2, a Web Services / SOAP / WSDL
 engine, the successor to the widely used Apache Axis SOAP stack.");
 script_xref(name : "URL" , value : "http://ws.apache.org/axis2/");

 script_tag(name: "qod_type", value: "remote_banner");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

infos = get_app_version_and_location( cpe:CPE, port:port );

dir = infos['location'];
if( ! dir ) exit( 0 );

vers = infos['version'];

if( "Server: Simple-Server" >< get_http_banner( port:port ) ) {
   #Axis2 running on binary distribution
   url = string( dir, "/services/" );
   sep =  '?wsdl">';
   pattern = '<a href="(.*)\\?wsdl">';
} else {
   #Axis2 running on tomcat or similar
   url = string( dir, "/services/listServices" );
   pattern = 'Service Description : <font color="black">(.*)</font>';
   sep = '\n';
}

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

#Needed for Axis2 0.9.3 and below
if( "/services/listServices.jsp" >< buf ) {
   url = string( dir, "/listServices" );
   req = http_get( item:url, port:port );
   buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

   cookie = eregmatch( pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:buf );

   host = http_host_name(port:port);

   req = 'GET ' + url + '.jsp HTTP/1.1\r\n' +
         'Host: ' + host + '\r\n' +
         'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
         'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
         'Accept-Language: en-US,en;q=0.5\r\n' +
         'Cookie: JSESSIONID=' + cookie[1] + '\r\n' +
         '\r\n';

   buf = http_keepalive_send_recv( port:port, data:req );
   pattern = host + dir + '/services/(.*)\\?wsdl">';
}

report = 'The following services were detected at ' + url + ' :\n';
found_service = 0;

if( vers != NULL ) {
   set_kb_item( name:"axis2/services",value:"Version" );
   report = report + '\nVersion';
   found_service = 1;
}

services = egrep( string: buf, pattern: pattern,icase:TRUE );

if( services ) {

   foreach service( split( services, sep:sep ) ) {

      match = eregmatch( string: service, pattern: pattern,icase:TRUE );
      if( !isnull( match[1] ) && match[1] != "Version" ) {
         set_kb_item( name:"axis2/services", value:match[1] );
         report = report + '\n' + match[1];
         found_service = 1;
      }
   }
   if( found_service ) log_message( data: report, port: port );
}

exit(0);
