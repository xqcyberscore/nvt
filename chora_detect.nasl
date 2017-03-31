# OpenVAS Vulnerability Test
# $Id: chora_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
# Description: Chora Detection
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

tag_summary = "This script detects whether the remote host is running Chora and
extracts version numbers and locations of any instances found. 

Chora is a PHP-based interface to CVS repositories from the Horde
Project. See http://www.horde.org/chora/ for more information.";

# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
  desc = "
  Summary:
  " + tag_summary;


if (description) {
  script_id(13849);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
 
  name = "Chora Detection";
  script_name(name);
 
 
  summary = "Checks for the presence of Chora";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "General";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.13849";
SCRIPT_DESC = "Chora Detection";

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: looking for Chora on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Search for Chora in a couple of different locations.
#
# NB: Directories beyond cgi_dirs() come from a Google search - 
#     'inurl:cvs.php horde' - and represent the more popular
#     installation paths currently. Still, cgi_dirs() should catch
#     the directory if its referenced elsewhere on the target.
dirs = make_list("/horde/chora", "/chora", "/", cgi_dirs());
installs = 0;
foreach dir (dirs) {
  # Search for version number in a couple of different pages.
  files = make_list(
    "/horde/services/help/?module=chora&show=about",
    "/cvs.php",
    "/README"
  );

  foreach file (files) {
    if (debug_level) display("checking for Chora in ", dir, file, "...\n");

    # Get the page.
    req = http_get(item:string(dir, file), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
      # Specify pattern used to identify version string.
      #
      # - version 2.x
      if (file == "/horde/services/help/?module=chora&show=about") {
        pat = '>This is Chora +(.+).<';
      }
      # - version 1.x
      else if (file =~ "^/cvs.php") {
        pat = 'class=.+>CHORA +(.+)</a>';
      }
      # - other possibilities, but not necessarily good ones.
      #   nb: README is not guaranteed to be available and is sometimes
      #       inaccurate (eg, it reads 1.0 in version 1.2 and 1.2.1 in
      #       version 1.2.2).
      else if (file == "/README") {
        pat = '^Version +(.+) *$';
      }
      # - someone updated files but forgot to add a pattern???
      else {
        if (debug_level) display("Don't know how to handle file '", file, "'!\n");
        exit(1);
      }

      # Get the version string.
      if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
        ver = eregmatch(pattern:pat, string:match);
        if (ver == NULL) break;
        ver = ver[1];
        if (debug_level) display("Chora version ", ver, " found in ", dir, ".\n");

        # Success!
        tmp_version = string(ver, " under ", dir);
        set_kb_item(
          name:string("www/", port, "/chora"), 
          value:tmp_version);

        installations[dir] = ver;
        ++installs;

        ## build cpe and store it as host_detail
        cpe = build_cpe(value: tmp_version, exp:"^([0-9.]+)",base:"cpe:/a:horde:chora:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        # nb: only worried about the first match.
        break;
      }
      # nb: if we found an installation, stop iterating through files.
      if (installs) break;
    }
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("Chora ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Chora were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = ereg_replace(
    string:desc,
    pattern:"This script[^\.]+\.", 
    replace:info
  );
  log_message(port:port, data:desc);
}
