# OpenVAS Vulnerability Test
# $Id: cvs_in_www.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: CVS/Entries
#
# Authors:
# Nate Haggard (SecurityMetrics inc.)
# changes by rd: pattern matching to determine if the file is CVS indeed
#
# Copyright:
# Copyright (C) 2002 Nate Haggard (SecurityMetrics inc.)
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

tag_summary = "Your website allows read access to the CVS/Entries file.  
This exposes all file names in your CVS module on your website.  
Change your website permissions to deny access to your CVS 
directory.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10922");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 name = "CVS/Entries";
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright("This script is Copyright (C) 2002 Nate Haggard (SecurityMetrics inc.)");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/no404/" + port) ) exit(0);

res = is_cgi_installed_ka(item:"/CVS/Entries", port:port);
# is_cgi_installed_ka takes care of servers that always return 200
# This was tested with nessus 1.2.1 
if(res)
{
 if (debug_level) display("cvs_in_www.nasl: ", res, "\n");

 soc = http_open_socket(port);
 file = string("/CVS/Entries");
 req = http_get(item:file, port:port);
 send(socket:soc, data:req);
 h = http_recv_headers2(socket:soc);
 r = http_recv_body(socket:soc, headers:h, length:0);
 http_close_socket(soc);

 warning = string("Your website allows read access to the CVS/Entries file.\n");
 warning += string("This exposes all file names in your CVS module on your website.\n\n");
 warning += string("Solution: Change your website permissions to deny access to your\n");
 warning += string("CVS directory.  Entries contains the following: \n", r);

  security_message(port:port, data:warning);
}
exit(0);
