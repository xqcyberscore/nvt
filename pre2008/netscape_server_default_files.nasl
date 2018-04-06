# OpenVAS Vulnerability Test
# $Id: netscape_server_default_files.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Netscape Enterprise Server default files
#
# Authors:
# David Kyger <david_kyger@symantec.com>
# Updated By: Antu Sanadi <santu@secpod> on 2010-07-06
# Updated CVSS Base
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

tag_summary = "Netscape Enterprise Server has default files installed.
Default files were found on the Netscape Enterprise Server.

These files should be removed as they may help an attacker to guess the
exact version of the Netscape Server which is running on this host.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12077");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  name = "Netscape Enterprise Server default files ";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("

Default installation files were found on the Netscape Enterprise Server

Remove default files from the web server.

These files should be removed as they may help an attacker to guess the
exact version of the Netscape Server which is running on this host.

The following default files were found:");

port = get_http_port(default:80);


if(get_port_state(port))
 {
  pat1 = "Netscape Enterprise Server Administrator's Guide";
  pat2 = "Enterprise Edition Administrator's Guide";
  pat3 = "Netshare and Web Publisher User's Guide";

  fl[0] = "/help/contents.htm";
  fl[1] = "/manual/ag/contents.htm";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf) || (pat2 >< buf) || (pat3 >< buf)) {
     warning = warning + string("\n", fl[i]);
     flag = 1;
     }
    }

    if (flag > 0) { 
     security_message(port:port, data:warning);
    }
}
