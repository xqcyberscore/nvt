# OpenVAS Vulnerability Test
# $Id: consolehelp.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: WebLogic source code disclosure
#
# Authors:
# John Lampe <j_lampe@bellsouth.net> 
# Modifications by Tenable Network Security :
# -> Check for an existing .jsp file, instead of /default.jsp
# -> Expect a jsp signature
#
# Copyright:
# Copyright (C) 2003 John Lampe
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

tag_summary = "There is a bug in the Weblogic web application.  Namely,
by inserting a /ConsoleHelp/ into a URL, critical source code
files may be viewed.";

tag_solution = "http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA02-03.jsp";

if(description)
{
 script_id(11724);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1518);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2000-0682");
 script_xref(name:"OSVDB", value:"1481");
 
 
 name = "WebLogic source code disclosure";
 script_name(name);
 


 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul"); 
 
 
 script_copyright("This script is Copyright (C) 2003 John Lampe");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

jspfiles = get_kb_list(string("www/", port, "/content/extensions/jsp"));

if(isnull(jspfiles))jspfiles = make_list("default.jsp");
else jspfiles = make_list(jspfiles);

cnt = 0;

foreach file (jspfiles)
{ 
 req = http_get(item:"/ConsoleHelp/" + file, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( "<%" >< res && "%>" >< res ) { security_message(port); exit(0); }
 cnt ++;
 if(cnt > 10)exit(0);
}
