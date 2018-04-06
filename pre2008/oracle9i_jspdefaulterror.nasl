# OpenVAS Vulnerability Test
# $Id: oracle9i_jspdefaulterror.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle 9iAS default error information disclosure
#
# Authors:
# Javier Fernandez-Sanguino <jfs@computer.org>
#
# Copyright:
# Copyright (C) 2003 Javier Fernandez-Sanguino
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

tag_solution = "Ensure that virtual paths of URL is different from the actual directory 
path. Also, do not use the <servletzonepath> directory in 
'ApJServMount <servletzonepath> <servletzone>' to store data or files.

Upgrading to Oracle 9iAS 1.1.2.0.0 will also fix this issue.



http://www.nextgenss.com/papers/hpoas.pdf";

tag_summary = "It is possible to obtain the physical path of the remote server
web root.

Description :

Oracle 9iAS allows remote attackers to obtain the physical path of a file
under the server root via a request for a non-existent .JSP file. The default
error generated leaks the pathname in an error message.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11226");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3341);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2001-1372");
 name = "Oracle 9iAS default error information disclosure";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2003 Javier Fernandez-Sanguino");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_xref(name : "URL" , value : "http://otn.oracle.com/deploy/security/pdf/jspexecute_alert.pdf");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/278971");
 script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-2002-08.html");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for the configuration file

     errorjsp = "/nonexistant.jsp";
     req = http_get(item: errorjsp, port: port);
     soc = http_open_socket(port);
     if(soc) {
        send(socket:soc, data:req);
         r = http_recv(socket:soc);
         http_close_socket(soc);
	 location = egrep(pattern:"java.io.FileNotFoundException", string :r);
	 if ( location )  {
 	 # Thanks to Paul Johnston for the tip that made the following line
	 # work (jfs)
         # MA 2005-02-13: This did not work on Windows where / is replaced by \
	     path = ereg_replace(pattern: strcat("(java.io.FileNotFoundException: )(.*[^/\])[/\]+",substr(errorjsp, 1),".*"), replace:"\2", string: location);
	     security_message(port:port, data:string("The web root physical is ", path ));
	 }
     } # if (soc)
}
