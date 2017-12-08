# OpenVAS Vulnerability Test
# $Id: dbman_cgi.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: DBMan CGI server information leakage
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd : 
#  - script_id
#  - script_bugtraq_id(1178);
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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

tag_summary = "It is possible to cause the DBMan 
CGI to reveal sensitive information, by requesting a URL such as:

GET /scripts/dbman/db.cgi?db=no-db";

tag_solution = "Upgrade to the latest version";

if(description)
{
 script_id(10403);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1178);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_cve_id("CVE-2000-0381");
 name = "DBMan CGI server information leakage";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
  if ( get_kb_item("Services/www/" + port + "/embedded" ) ) exit(0);
  req = http_get(item:"/scripts/dbman/db.cgi?db=no-db",
  		port:port);
  soc = http_open_socket(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = http_recv(socket:soc);
   http_close_socket(soc);
   backup = result;
   report = string("\nIt is possible to cause the DBMan\n", 
"CGI to reveal sensitive information, by requesting a URL such as:\n\n",
"GET /scripts/dbman/db.cgi?db=no-db\n\n",
"We could obtain the following : \n\n");
   if("CGI ERROR" >< result)
   {
    result = strstr(backup, string("name: no-db at "));
    result = result - strstr(result, string(" line "));
    result = result - "name: no-db at ";
    report = "CGI full path is at: " + result + string("\n");

    result = strstr(backup, string("Perl Version        : "));
    result = result - strstr(result, string("\n"));
    result = result - string("Perl Version        : ");
    report = report + "Perl version: " + result + string("\n");

    result = strstr(backup, string("PATH                : "));
    result = result - strstr(result, string("\n"));
    result = result - string("PATH                : ");
    report = report + "Server path: " + result + string("\n");

    result = strstr(backup, string("SERVER_ADDR         : "));
    result = result - strstr(result, string("\n"));
    result = result - string("SERVER_ADDR         : ");
    report = report + "Server real IP: " + result + string("\n");

    result = strstr(backup, string("SERVER_SOFTWARE     : "));
    result = result - strstr(result, string("\n"));
    result = result - string("SERVER_SOFTWARE     : ");
    report = report + "Server software: " + result + string("\n");
    report = report + string("\nSolution : Upgrade to the latest version\n");
    security_message(port, data: report);
   } 
  }
}

