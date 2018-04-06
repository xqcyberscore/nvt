# OpenVAS Vulnerability Test
# $Id: gosmart_message_board.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: GoSmart message board multiple flaws
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is running GoSmart message board, a bulletin board 
manager written in ASP.


The remote version of this software contains multiple flaws, due o
to a failure of the application to properly sanitize user-supplied input.

It is also affected by a cross-site scripting vulnerability. 
As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

Furthermore, this version is vulnerable to SQL injection flaws that
let an attacker inject arbitrary SQL commands.";

tag_solution = "Upgrade to the newest version of this software";

#  Ref: Alexander Antipov <antipov SecurityLab ru> - MAxpatrol Security

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15451");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1588", "CVE-2004-1589");
 script_bugtraq_id(11361);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("GoSmart message board multiple flaws");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir( make_list_unique( "/messageboard", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = string(dir, "/Forum.asp?QuestionNumber=1&Find=1&Category=%22%3E%3Cscript%3Efoo%3C%2Fscript%3E%3C%22");
  req = http_get(item:req, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) continue;

  if (r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r)) {
    security_message(port);
    exit(0);
  }
}
