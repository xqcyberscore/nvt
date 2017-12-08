# OpenVAS Vulnerability Test
# $Id: ibm_server_code.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: IBM-HTTP-Server View Code
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2001 Felix Huber
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

tag_summary = "IBM's HTTP Server on the AS/400 platform is vulnerable to an attack
that will show the source code of the page -- such as an .html or .jsp
page -- by attaching an '/' to the end of a URL.

Example:
http://www.example.com/getsource.jsp/";

tag_solution = "Not yet";

# v. 1.00 (last update 08.11.01)

if(description)
{
 script_id(10799);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3518);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 name = "IBM-HTTP-Server View Code";
 script_name(name);





 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");


 script_copyright("This script is Copyright (C) 2001 Felix Huber");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_dependencies("httpver.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ibm-http");
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


dir[0] = "/index.html";
dir[1] = "/index.htm";
dir[2] = "/index.jsp";
dir[3] = "/default.html";
dir[4] = "/default.htm";
dir[5] = "/default.jsp";
dir[6] = "/home.html";
dir[7] = "/home.htm";
dir[8] = "/home.jsp";


files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if(!isnull(files))
{
 files = make_list(files);
 if(files[0])dir[9] = files[0];
}

if(get_port_state(port))
{

 for (i = 0; dir[i] ; i = i + 1)
 {
    
	req = http_get(item:string(dir[i], "/"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if(r == NULL)exit(0);
	if("Content-Type: www/unknown" >< r)
	    {
                    	security_message(port);
                     	exit(0);
	    }

  }
}

