# OpenVAS Vulnerability Test
# $Id: mailman_detect.nasl 5737 2017-03-27 14:18:12Z cfi $
# Description: Mailman Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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

tag_summary = "This script detects whether the remote host is running Mailman and
extracts version numbers and locations of any instances found. 

Mailman is a Python-based mailing list management package from the GNU
Project.  See http://www.list.org/ for more information.";
 
if(description)
{
  script_id(16338);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 5737 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-27 16:18:12 +0200 (Mon, 27 Mar 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Mailman Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("General");
  script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

# Search for Mailman's listinfo page.
installs = 0;
foreach dir( make_list_unique( "/mailman", cgi_dirs( port:port ) ) ) {
  listinfo = string(dir, "/listinfo");
  debug_print("testing '", listinfo, "'.");
  if (dir == "") dir = "/";

  # Get the page.
  req = http_get(item:listinfo, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect
  debug_print("result = >>", res, "<<.");

  # Find the version number. It will be in a line such as
  #   <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.5</td>
  pat = "alt=.Delivered by Mailman..+>version ([^<]+)";
  debug_print("grepping results for =>>", pat, "<<.");
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    debug_print("grepping >>", match, "<< for =>>", pat, "<<.");
    ver = eregmatch(pattern:pat, string:match);
    if (ver == NULL) break;
    ver = ver[1];
    debug_print("Mailman version =>>", ver, "<<.");

    # Success!
    set_kb_item(
      name:string("www/", port, "/Mailman"), 
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;

    # nb: only worried about the first match.
    break;
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
    info = string("Mailman ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Mailman were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  log_message(port:port, data:info);
}
