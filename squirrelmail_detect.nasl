# OpenVAS Vulnerability Test
# $Id: squirrelmail_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
# Description: SquirrelMail Detection
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

tag_summary = "The remote web server contains a webmail application. 

  Description :
  The remote host is running SquirrelMail, a PHP-based webmail package
  that provides access to mail accounts via POP3 or IMAP.";

if (description) {
  script_id(12647);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  name = "SquirrelMail Detection";
  script_name(name);
 
 
  summary = "Checks for the presence of SquirrelMail";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Service detection";
  script_family(family);

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_xref(name : "URL" , value : "http://www.squirrelmail.org/");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.12647";
SCRIPT_DESC = "SquirrelMail Detection";

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for SquirrelMail.
foreach dir (make_list("/squirrelmail", "/webmail", "/mail", "/sm", cgi_dirs()))
{
  req = http_get(item:string(dir, "/src/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);
  if (!egrep(pattern:"<title>Squirrel[mM]ail - Login</title>", string:res)) continue;

  # Search in a couple of different pages.
  files = make_list(
    "/src/login.php", "/src/compose.php", "/ChangeLog", "/ReleaseNotes"
  );
  foreach file (files) {
    if (file != "/src/login.php") {
      # Get the page.
      req = http_get(item:string(dir, file), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if (res == NULL) exit(0);
    }

    # Specify pattern used to identify version string.
    if (file == "/src/login.php" || file == "/src/compose.php") {
      pat = "<SMALL>SquirrelMail version (.+)<BR";
    }
    else if (file == "/ChangeLog") {
      pat = "^Version (.+) - [0-9]";
    }
    # nb: this first appeared in 1.2.0 and isn't always accurate.
    else if (file == "/ReleaseNotes") {
      pat = "Release Notes: SquirrelMail (.+) *\*";
    }
    # - someone updated files but forgot to add a pattern???
    else {
      #if (log_verbosity > 1) debug_print("don't know how to handle file '", file, "'!", level:0);
      exit(1);
    }

    # Get the version string.
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match, icase:TRUE);
      if (ver == NULL) break;
      ver = ver[1];

      # Success!
      tmp_version = string(ver, " under ", dir);
      set_kb_item(
        name:string("www/", port, "/squirrelmail"),
        value:tmp_version);

      installations[dir] = ver;
      ++installs;

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)",base:"cpe:/a:squirrelmail:squirrelmail:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      # nb: only worried about the first match.
      break;
    }
    # nb: if we found an installation, stop iterating through files.
    if (installs) break;
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs ) break;
}

info = "";

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("SquirrelMail ", ver, " was detected on the remote host under the\npath '", dir, "'.");
  }
  else {
    info = string(
      "Multiple instances of SquirrelMail were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under '", dir, "'\n");
    }
    info = chomp(info);
  }

  log_message(port:port, data:info);
}
