# OpenVAS Vulnerability Test
# $Id: guestbook.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: guestbook.cgi
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
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

tag_summary = "The 'guestbook.cgi' is installed. This CGI has
 a well known security flaw that lets anyone execute arbitrary
 commands with the privileges of the http daemon (root or nobody).";

tag_solution = "remove it from /cgi-bin.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10098");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(776);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_cve_id("CVE-1999-0237"); 
 name = "guestbook.cgi";
 script_name(name);





   

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");

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
exit(0); # FPs
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"guestbook.cgi", port:port);
if(res)
{
 security_message(port);
}
   
