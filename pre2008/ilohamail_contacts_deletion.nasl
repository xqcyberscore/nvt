# OpenVAS Vulnerability Test
# $Id: ilohamail_contacts_deletion.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Anaconda Double NULL Encoded Remote File Retrieval
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
0.7.9-RC2 or earlier.  Such versions contain a flaw that enables an
authenticated user to delete contacts belonging to any user provided
the DB-based backend is used to store contacts.  The flaw arises
because ownership of 'delete_item' is not checked when deleting
entries in include/save_contacts.MySQL.inc. 

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number of IlohaMail 
***** installed there.";

tag_solution = "Upgrade to IlohaMail version 0.7.9 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.14633");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"OSVDB", value:"7402");
 
  name = "IlohaMail Contacts Deletion Vulnerability";
  script_name(name);
 
  summary = "Checks for Contacts Deletion vulnerability in IlohaMail";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail Contacts Deletion vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ver =~ "^0\.([0-6].*|7\.([0-8](-Devel)?|9-.+)$)") {
      security_message(port);
      exit(0);
    }
  }
}
