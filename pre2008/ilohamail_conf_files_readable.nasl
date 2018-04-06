# OpenVAS Vulnerability Test
# $Id: ilohamail_conf_files_readable.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IlohaMail Readable Configuration Files
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

tag_summary = "The target is running at least one instance of IlohaMail that allows
anyone to retrieve its configuration files over the web.  These files
may contain sensitive information. For example, conf/conf.inc may
hold a username / password used for SMTP authentication.";

tag_solution = "Upgrade to IlohaMail version 0.8.14-rc2 or later or
reinstall following the 'Proper Installation' instructions in the
INSTALL document.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.16142");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(12252);

  name = "IlohaMail Readable Configuration Files";
  script_name(name);
 
 
  summary = "Checks for Readable Configuration Files in IlohaMail";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2005 George A. Theall");

  family = "Remote file access";
  script_family(family);

  script_dependencies("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("searching for readable configuration files in IlohaMail on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    # If this was a quick & dirty install, try to grab a config file.
    if (dir =~ "/source$") {
      dir = ereg_replace(string:dir, pattern:"/source$", replace:"/conf");
      # nb: conf.inc appears first in 0.7.3; mysqlrc.inc was used
      #     as far back as 0.7.0.
      foreach config (make_list("conf.inc", "mysqlrc.inc")) {
        url = string(dir, "/", config);
        debug_print("retrieving ", url, "...");
        req = http_get(item:url, port:port);
        res = http_keepalive_send_recv(port:port, data:req);
        if (res == NULL) exit(0);           # can't connect
        debug_print("res =>>", res, "<<.");

        # Does it look like PHP code with variable definitions?
        if (egrep(string:res, pattern:"<\?php") && egrep(string:res, pattern:"\$[A-Za-z_]+ *= *.+;")) {
#        if (egrep(string:res, pattern:"<\?php")) {
#          display("It's php code!\n");
#          if (egrep(string:res, pattern:"\$[A-Za-z_]+ *= *.+;")) {
#            display("It's got variable assignments!\n");
          security_message(port:port);
          exit(0);
#}
        }
      }
    }
  }
}
