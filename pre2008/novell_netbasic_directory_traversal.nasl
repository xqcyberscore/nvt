# OpenVAS Vulnerability Test
# $Id: novell_netbasic_directory_traversal.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Novell Netbasic Scripting Server Directory Traversal
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
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

tag_summary = "Novell Netbasic Scripting Server Directory Traversal

It is possible to escape out of the root directory of the scripting server by 
substituting a forward or backward slash for %5C. As a result, system 
information, such as environment and user information, could be obtained from 
the Netware server.

Example: http://server/nsn/..%5Cutil/userlist.bas";

tag_solution = "Apply the relevant patch and remove all default files from their
respective directories.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12050");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5523);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1417");

 name = "Novell Netbasic Scripting Server Directory Traversal";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "Netware";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
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

function check(req)
{
 http = http_get(item:req, port:port);
 res = http_keepalive_send_recv(port:port, data:http);
 if ( res == NULL ) exit(0);
 pattern = "Error running script";
 pattern2 = "Module load Failed";

 if((pattern >!< r) && (pattern2 >!< r)) {
	# Work around some 'smart' modules
 	http = http_get(item:req + 'foo', port:port);
 	res = http_keepalive_send_recv(port:port, data:http);
 	if ( res == NULL ) exit(0);
	if ( egrep(pattern:"^HTTP/.* 200 .*", string:res) ) return 0;
        else return(1);
        }
 return(0);
}

flag = 0;

warning = string("
It is possible to escape out of the root directory of the scripting server by 
substituting a forward or backward slash for %5C. As a result, system 
information, such as environment and user information, could be obtained from 
the Netware server.

The following Novell scripts can be executed on the server:");

port = get_http_port(default:80);

if(get_port_state(port)) {

        pat1 = "Statistics for volume";
        pat2 = "used by files";
        pat3 = "Novell Script For NetWare";
        pat4 = "Directory Of";
        pat5 = "====================================================";
        pat6 = "User:";
        pat7 = "Media Type";
        pat8 = "Interrupt Secondary";
        pat9 = "SYS:NSN\\WEB\\";
        pat10 = "SYS:NSN\\TEMP\\";
        pat11 = "NOT-LOGGED-IN"; 
        pat12 = "--------------";
        pat13 = "ADMSERV_ROOT";
        pat14 = "ADMSERV_PWD";
        pat15 = "Directory Listing Tool";
        pat16 = "Server Name";

	fl[0] = "/nsn/..%5Cutil/chkvol.bas";
	fl[1] = "/nsn/..%5Cutil/dir.bas";
	fl[2] = "/nsn/..%5Cutil/glist.bas";
	fl[3] = "/nsn/..%5Cutil/lancard.bas";
	fl[4] = "/nsn/..%5Cutil/set.bas";
	fl[5] = "/nsn/..%5Cutil/userlist.bas";
	fl[6] = "/nsn/..%5Cweb/env.bas";
	fl[7] = "/nsn/..%5Cwebdemo/fdir.bas"; 

   for(i=0;fl[i];i=i+1) {
   req = http_get(item:fl[i], port:port);
   buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat8 >< buf) || (pat9 >< buf && pat10 >< buf) || (pat11 >< buf && pat12 >< buf) || (pat13 >< buf && pat14 >< buf) || (pat15 >< buf && pat16 >< buf)) {
	warning = warning + string("\n", fl[i]);
        flag = 1;
	}
    }
    if (flag > 0) {
	warning += string("\n\nSolution: Apply the relevant patch and remove all default files from their respective directories.\n\n");
        security_message(port:port, data:warning);
    } else {
      exit(0);
      }
}


