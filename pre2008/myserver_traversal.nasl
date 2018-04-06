# OpenVAS Vulnerability Test
# $Id: myserver_traversal.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: myServer 0.4.3 / 0.7 Directory Traversal Vulnerability
#
# Authors:
# Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2003 Westpoint Ltd
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

tag_summary = "This web server is running myServer <= 0.4.3 or 0.7. This version contains
a directory traversal vulnerability, that allows remote users with
no authentication to read files outside the webroot.

You have to create a dot-dot URL with the same number of '/./' and '/../'
+ 1. For example, you can use :
/././..
/./././../..
/././././../../..
/./././././../../../..
etc...
or a long URL starting with ./././. etc.

More information : http://www.securityfocus.com/archive/1/339145";

tag_solution = "Upgrade to myServer 0.7.1 or later";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11851");
 script_version("$Revision: 9348 $");
 script_cve_id("CVE-2004-2516");
 script_bugtraq_id(11189);
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "myServer 0.4.3 / 0.7 Directory Traversal Vulnerability";
 script_name(name);




 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("Copyright (C) 2003 Westpoint Ltd");
 script_family("Web application abuses");

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# In fact, myServer 0.7 is also vulnerable to the first URL.
# However, as the bug was supposed to be fixed in 0.4.3 and reappeared in 
# 0.7, I think that checking every avatar is safer.

foreach pattern (make_list("/././..", "././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././../../../../../../../../"))
{
 req = http_get(item: pattern, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL) exit(0);

 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res)
    && egrep(pattern:"Contents of folder \.\.", string:res, icase:1))
 {
  security_message(port);
  exit(0);
 }
}
