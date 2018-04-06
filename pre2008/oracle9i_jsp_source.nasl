# OpenVAS Vulnerability Test
# $Id: oracle9i_jsp_source.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle 9iAS Jsp Source File Reading
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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

tag_summary = "In a default installation of Oracle 9iAS it is possible to read the source of 
JSP files. When a JSP is requested it is compiled 'on the fly' and the 
resulting HTML page is returned to the user. Oracle 9iAS uses a folder to hold 
the intermediate files during compilation. These files are created in the same 
folder in which the .JSP page resides. Hence, it is possible to access the 
.java and compiled .class files for a given JSP page.";

tag_solution = "Edit httpd.conf to disallow access to the _pages folder.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10852");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4034);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2002-0562");
 name = "Oracle 9iAS Jsp Source File Reading";
 script_name(name);
 
 script_xref(name : "URL" , value : "http://wwww.nextgenss.com/advisories/orajsa.txt");
 script_xref(name : "URL" , value : "http://www.oracle.com");

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache"); 
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
# This plugin uses a demo jsp to test for this vulnerability. It would be 
# better to use the output of webmirror.nasl to find valid .jsp pages
# which could then be used in the test. In situations where the demo pages
# have been removed this plugin will false negative.
 
 req = http_get(item:"/demo/ojspext/events/index.jsp", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("This page has been accessed" >< r)	
	req = http_get(item:"/demo/ojspext/events/_pages/_demo/_ojspext/_events/_index.java", port:port);
	soc = http_open_socket(port);
	if(soc)
	{
	send(socket:soc, data:req);
	r = http_recv(socket:soc);
	http_close_socket(soc);
	
	if("import oracle.jsp.runtime.*" >< r)security_message(port);
  }
 }
}
