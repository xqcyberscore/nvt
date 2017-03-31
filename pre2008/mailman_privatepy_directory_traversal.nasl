# OpenVAS Vulnerability Test
# $Id: mailman_privatepy_directory_traversal.nasl 3441 2016-06-06 20:27:46Z jan $
# Description: Mailman private.py Directory Traversal Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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

tag_summary = "Authenticated Mailman users can view arbitrary files on the remote
host. 

Description : 

According to its version number, the remote installation of Mailman
reportedly is prone to a directory traversal vulnerability in
'Cgi/private.py'.  The flaw comes into play only on web servers that
don't strip extraneous slashes from URLs, such as Apache 1.3.x, and
allows a list subscriber, using a specially crafted web request, to
retrieve arbitrary files from the server - any file accessible by the
user under which the web server operates, including email addresses
and passwords of subscribers of any lists hosted on the server.  For
example, if '$user' and '$pass' identify a subscriber of the list
'$listname@$target', then the following URL :

  http://$target/mailman/private/$listname/.../....///mailman?username=$user&password=$pass

allows access to archives for the mailing list named 'mailman' for
which the user might not otherwise be entitled.";

tag_solution = "Upgrade to Mailman 2.1.6b1 or apply the fix referenced in the first
URL above.";
 
if (description) {
  script_id(16339);
  script_version("$Revision: 3441 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-06 22:27:46 +0200 (Mon, 06 Jun 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2005-0202");
  script_bugtraq_id(12504);
  script_xref(name:"OSVDB", value:"13671");
 
  name = "Mailman private.py Directory Traversal Vulnerability";
  script_name(name);
 
  summary = "Checks for Mailman private.py Directory Traversal Vulnerability";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");

  script_copyright("This script is Copyright (C) 2005 George A. Theall");

  script_dependencies("mailman_detect.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://mail.python.org/pipermail/mailman-announce/2005-February/000076.html");
  script_xref(name : "URL" , value : "http://lists.netsys.com/pipermail/full-disclosure/2005-February/031562.html");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# Web servers to ignore because it's known they strip extra slashes from URLs.
#
# nb: these can be regex patterns.
web_servers_to_ignore = make_list(
  "Apache(-AdvancedExtranetServer)?/2",                      # Apache 2.x
  'Apache.*/.* \\(Darwin\\)'
);

# Skip check if the server's type and version indicate it's not a problem
banner = get_http_banner(port: port);
if (banner) {
  web_server = strstr(banner, "Server:");
  if (web_server) {
    web_server = web_server - "Server: ";
    web_server = web_server - strstr(web_server, '\r');
    foreach pat (web_servers_to_ignore) {
      if (ereg(string:web_server, pattern:pat)) {
        debug_print("skipping because web server claims to be '", web_server, "'.");
        exit(0);
      }
    }
  }
}


# Test an install.
install = get_kb_item(string("www/", port, "/Mailman"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^2\.(0.*|1($|[^0-9.]|\.[1-5]($|[^0-9])))") {
    security_message(port);
  }
}
