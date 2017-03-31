# OpenVAS Vulnerability Test
# $Id: openwebmail_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
# Description: Open WebMail Detection
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

tag_summary = "This script detects whether the target is running Open WebMail and
extracts version numbers and locations of any instances found. 

Open WebMail is a webmail package written in Perl that provides access
to mail accounts via POP3 or IMAP.  See <http://www.openwebmail.org/>
for more information.";

if (description)
{
  script_id(14221);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  name = "Open WebMail Detection";
  script_name(name);

  summary = "Checks for the presence of Open WebMail";
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

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);
if (debug_level) display("debug: looking for Open WebMail on ", host, ":", port, ".\n");

# Search for Open WebMail in a couple of different locations.
#
# NB: Directories beyond cgi_dirs() come from a Google search - 
#     'inurl:openwebmail.pl userid' - and represent the more popular
#     installation paths currently. Still, cgi_dirs() should catch
#     the directory if its referenced elsewhere on the target.
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/cgi-bin/openwebmail", 1,
  "/openwebmail-cgi", 1
);
foreach dir (dirs) {
  # Set value to zero if it's already in dirs.
  if (!isnull(xtra_dirs[dir])) xtra_dirs[dir] = 0;
}
foreach dir (keys(xtra_dirs)) {
  # Add it to dirs if the value is still set.
  if (xtra_dirs[dir]) dirs = make_list(dirs, dir);
}

installs = 0;
foreach dir (dirs) {
  url = string(dir, "/openwebmail.pl");
  if (debug_level) display("debug: retrieving ", url, "...\n");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (isnull(res)) exit(0);             # can't connect
  if (debug_level) display("debug: res =>>", res, "<<\n");

  # If the page refers to Open WebMail, try to get its version number.
  if (
    egrep(string:res, pattern:"^HTTP/.* 200 OK") &&
    egrep(string:res, pattern:"(http://openwebmail\.org|Open WebMail)")
  ) {
    # First see if version's included in the form. If it is, Open WebMail 
    # puts it on a line by itself, prefixed by the word "version".
    pat = "^version (.+)$";
    if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) ver = ver[1];
      break;                            # nb: only worried about first match.
    }

    # If that didn't work, looking for it in doc/changes.txt,
    # under the Open WebMail data directory.
    if (isnull(ver)) {
      # Identify data directory from links to images or help files.
      pat = '([^\'"]*/openwebmail)/(images|help)/';
      if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
        data_url = eregmatch(string:match, pattern:pat);
        if (!isnull(data_url)) data_url = data_url[1];
        break;                          # nb: only worried about first match.
      }
      # Try to get doc/changes.txt under data directory.
      if (!isnull(data_url)) {
        if (debug_level) display("debug: url for data files =>>", data_url, "<<\n");
        url = string(data_url, "/doc/changes.txt");
        if (debug_level) display("debug: retrieving ", url, "...\n");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req);
        if (isnull(res)) exit(0);       # can't connect
        if (debug_level) display("debug: res =>>", res, "<<\n");

        # Try to get version number.
        #
        # nb: this won't identify intermediate releases, only full ones.
        if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
          pat = "^[0-1][0-9]/[0-3][0-9]/20[0-9][0-9]( +.version .+)?";
          if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
          matches = egrep(pattern:pat, string:res);
          foreach match (split(matches)) {
            match = chomp(match);
            if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
            ver = eregmatch(pattern:"version +(.+).$", string:match);
            if (isnull(ver)) {
              # nb: only first release date matters.
              if (isnull(rel)) {
                # Rearrange date: mm/dd/yyyy -> yyyyddmm.
                parts = split(match, sep:"/", keep:FALSE);
                rel = string(parts[2], parts[0], parts[1]);
              }
            }
            else {
              ver = ver[1];
              if (!isnull(rel)) ver = string(ver, " ", rel);
              break;                    # nb: only worried about first match.
            }
          }
        }
      }
    }

    # nb: in the event the version number is still unknown, I want 
    #     to record the fact that there's *some* version installed.
    if (isnull(ver)) {
      ver = "*** VERSION UNKNOWN ***";
      if (log_verbosity > 1) display("Can't determine version of Open WebMail installed under ", dir, " on ", host, ":", port, "!\n");
    }

    if (debug_level) display("debug: Open WebMail version =>>", ver, "<<\n");
    set_kb_item(
      name:string("www/", port, "/openwebmail"), 
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;
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
    info = string("Open WebMail ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Open WebMail were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  log_message(port:port, data:info);
}
