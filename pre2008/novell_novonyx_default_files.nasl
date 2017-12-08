# OpenVAS Vulnerability Test
# $Id: novell_novonyx_default_files.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Default Novonyx Web Server Files
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

tag_summary = "Novell Netware default Novonyx web server files.

A default installation of Novell 5.x will install the Novonyx web server. 
Numerous web server files included with this installation could reveal system 
information.";

tag_solution = "Delete the default pages";

if(description)
{
  script_id(12049);
  script_version("$Revision: 8023 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1634");
  script_bugtraq_id(4874);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "Default Novonyx Web Server Files";
 script_name(name);
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "Netware";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


flag = 0;

warning = string("
A default installation of Novell 5.x will install the Novonyx web server. 
Numerous web server files included with this installation could reveal system 
information.  

The following Novonyx web server files were found on the server:");

port = get_http_port(default:80);

   pat1 = "NetBasic WebPro Demo";
   pat2 = "Novell";
   pat3 = "ScriptEase:WSE";
   pat4 = "ALLFIELD.JSE";
   pat5 = "LAN Boards";
   pat6 = "Media Type";
   pat7 = "Login to NDS";
   pat8 = "Total Space";
   pat9 = "Free Space";
   pat10 = "SERVER_SOFTWARE";
   pat11 = "GATEWAY_INTERFACE";
   pat12 = "ADMSERV_ROOT";
   pat13 = "ADMSERV_PWD";
   pat14 = "Directory Listing Tool";
   pat15 = "Server Name";
   pat16 = "Source directory";
   pat17 = "secure directories sys";

   fl[0] = "/netbasic/websinfo.bas";
   fl[1] = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/misc/allfield.jse";
   fl[2] = "/lcgi/sewse.nlm?sys:/novonyx/suitespot/docs/sewse/misc/test.jse";
   fl[3] = "/perl/samples/lancgi.pl";
   fl[4] = "/perl/samples/ndslogin.pl";
   fl[5] = "/perl/samples/volscgi.pl";
   fl[6] = "/perl/samples/env.pl";
   fl[7] = "/nsn/env.bas";
   fl[8] = "/nsn/fdir.bas";

 
   for(i=0;fl[i];i=i+1) 
   { 
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat2 >< buf) || (pat8 >< buf && pat9 >< buf) || (pat10 >< buf && pat11 >< buf) || (pat12 >< buf && pat13 >< buf) || (pat14 >< buf && pat15 >< buf) || (pat16 >< buf && pat17 >< buf)) {
        warning = warning + string("\n", fl[i]); 
        flag = 1;
        }
   }
    if (flag > 0) {
	warning += string("\n\nSolution: If not required, remove all default Novonyx web server files\n");
        security_message(port:port, data:warning);
        } else {
          exit(0);
        }
