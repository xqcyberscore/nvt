# OpenVAS Vulnerability Test
# $Id: imp_detect.nasl 9633 2018-04-26 14:07:08Z jschulte $
# Description: IMP Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12643");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9633 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-26 16:07:08 +0200 (Thu, 26 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IMP Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("General");
  script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "summary" , value : "This script detects whether the remote host is running IMP and extracts
version numbers and locations of any instances found.

IMP is a PHP-based webmail package from The Horde Project that provides
access to mail accounts via POP3 or IMAP. See
http://www.horde.org/imp/ for more information.");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Search for IMP in a couple of different locations.
#
# NB: Directories beyond cgi_dirs() come from a Google search -
#     'intitle:"welcome to" horde' - and represent the more popular
#     installation paths currently. Still, cgi_dirs() should catch
#     the directory if its referenced elsewhere on the target.
installs = 0;
foreach dir( make_list_unique( "/webmail", "/horde/imp", "/email", "/imp", "/mail", cgi_dirs( port:port ) ) ) {

  res = http_get_cache(port:port, item:dir + "/");
  if ( res == NULL || "IMP: Copyright 200" >!< res ) continue;

  # Search for version number in a couple of different pages.
  files = make_list(
    "/services/help/?module=imp&show=about",
    "/docs/CHANGES", "/test.php", "/README", "/lib/version.phps",
    "/status.php3"
  );
  foreach file (files) {
    if (debug_level) display("debug: checking ", dir, file, "...\n");

    res = http_get_cache(item:string(dir, file), port:port);
    if (res == NULL) continue;           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:"^HTTP/.\.. 200 ")) {
      # Specify pattern used to identify version string.
      # - version 4.x
      if (file =~ "^/services/help") {
        pat = ">This is Imp (.+)\.<";
      }
      # - version 3.x
      else if (file == "/docs/CHANGES") {
        pat = "^ *v(.+) *$";
      }
      #   nb: test.php available is itself a vulnerability but sometimes available.
      else if (file == "/test.php") {
        pat = "^ *<li>IMP: +(.+) *</li> *$";
      }
      #   nb: README is not guaranteed to be either available or accurate!!!
      else if (file == "/README") {
        pat = "^Version +(.+) *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps") {
        pat = "IMP_VERSION', '(.+)'";
      }
      # - version 2.x
      else if (file == "/status.php3") {
        pat = ">IMP, Version (.+)<";
      }
      # - someone updated files but forgot to add a pattern???
      else {
        if (debug_level) display("Don't know how to handle file '", file, "'!\n");
        exit(1);
      }

      if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
        ver = eregmatch(pattern:pat, string:match);
        if (ver == NULL) break;
        ver = ver[1];
        if (debug_level) display("debug: IMP version =>>", ver, "<<\n");

        # Success!
        set_kb_item(
          name:string("www/", port, "/imp"),
          value:string(ver, " under ", dir)
        );
        installations[dir] = ver;
        ++installs;

        # nb: only worried about the first match.
        break;
      }
      # nb: if we found an installation, stop iterating through files.
      if (installs) break;
    }
  }
  if (installs) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("IMP ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of IMP were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  log_message(port:port, data:info);
}
