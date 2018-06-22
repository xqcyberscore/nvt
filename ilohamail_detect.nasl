##############################################################################
# OpenVAS Vulnerability Test
# $Id: ilohamail_detect.nasl 10285 2018-06-21 12:22:45Z cfischer $
#
# Description: IlohaMail Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004-2005 George A. Theall
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14629");
  script_version("$Revision: 10285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-21 14:22:45 +0200 (Thu, 21 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IlohaMail Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004-2005 George A. Theall");
  script_family("General");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects whether the remote host is running IlohaMail and
  extracts version numbers and locations of any instances found.

  IlohaMail is a webmail application that is based on a stock build of
  PHP and that does not require either a database or a separate IMAP
  library. See <http://www.ilohamail.org/> for more information.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Search for IlohaMail in a couple of different locations.
#
# NB: Directories beyond cgi_dirs() come from a Google search -
#     'intitle:ilohamail "powered by ilohamail"' - and represent the more
#     popular installation paths currently. Still, cgi_dirs() should
#     catch the directory if its referenced elsewhere on the target.
installs = 0;

foreach dir( make_list_unique( "/webmail", "/ilohamail", "/IlohaMail", "/mail", cgi_dirs( port:port ) ) ) {

  res = http_get_cache(port:port, item:dir + "/");
  if ( res == NULL || "IlohaMail" >!< res ) continue;

  # For proper as well as quick & dirty installs.
  foreach src (make_list("", "/source")) {
    url = string(dir, src, "/index.php");

    res = http_get_cache(item:url, port:port);
    if (res == NULL) continue; # can't connect

    if (!http_40x(port:port, code:res)) {
      # Make sure the page is for IlohaMail.
      if (
        egrep(string:res, pattern:'>Powered by <a href="http://ilohamail.org">IlohaMail<') ||
        egrep(string:res, pattern:"<h2>Welcome to IlohaMail") ||
        (
          egrep(string:res, pattern:'<input type="hidden" name="logout" value=0>') &&
          egrep(string:res, pattern:'<input type="hidden" name="rootdir"') &&
          egrep(string:res, pattern:'<input type="password" name="password" value="" size=15')
        )
      ) {
        # Often the version string is embedded in index.php.
        ver = strstr(res, "<b> Version ");
        if (ver != NULL) {
          ver = ver - "<b> Version ";
          if (strstr(res, "</b>")) ver = ver - strstr(ver, "</b>");
          ver = ereg_replace(string:ver, pattern:"-stable", replace:"", icase:TRUE);
        }

        # Handle reporting.
        if (isnull(ver)) {
          ver = "unknown";
        }

        set_kb_item(
          name:string("www/", port, "/ilohamail"),
          value:string(ver, " under ", dir, src)
        );
        installations[string(dir,src)] = ver;
        ++installs;
      }
    }
    # nb: it's either a proper or a quick & dirty install.
    if (installs) break;
  }
  if (installs ) break;
}

if (installs) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    if (ver == "unknown") {
      info = string("An unknown version of IlohaMail was detected on the remote\nhost under the path ", dir, ".");
    }
    else {
      info = string("IlohaMail ", ver, " was detected on the remote host under the path ", dir, ".");
    }
  }
  else {
    info = string(
      "Multiple instances of IlohaMail were detected on the remote host:\n",
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
