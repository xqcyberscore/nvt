# OpenVAS Vulnerability Test
# $Id: burning_board_database_sql_injection.nasl 10033 2018-05-31 07:51:19Z ckuersteiner $
# Description: Woltlab Burning Board SQL injection flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

# ref: admin@batznet.com and Mustafa Can Bjorn

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80050");
  script_version("$Revision: 10033 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-31 09:51:19 +0200 (Thu, 31 May 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_bugtraq_id(15214, 16914);
  script_cve_id("CVE-2005-3369", "CVE-2006-1094");
  script_xref(name:"OSVDB", value:"20330");
  script_xref(name:"OSVDB", value:"23596");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Woltlab Burning Board SQL injection flaw");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2006 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_tag(name: "solution", value: "Unknown at this time.");
  script_tag(name: "summary", value: "The remote web server contains a PHP script that is susceptible to SQL
injection attacks.

Description:

The remote version of Burning Board includes an optional module, the Database module, that fails to properly
sanitize the 'fileid' parameter of the 'info_db.php' script, which can be exploited to launch SQL injection
attacks against the affected host.");

  script_xref(name: "URL", value: "http://www.securityfocus.com/archive/1/426583/30/0/threaded");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!port) exit(0);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test any installs: this can fork()
install = get_kb_item(string("www/", port, "/BurningBoard"));

if (!isnull(install)) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    loc = matches[2];
    buf = http_get(item:string(loc,"/info_db.php?action=file&fileid=1/**/UNION/**/SELECT/**/"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if(r == NULL)exit(0);
    if(("Database error in WoltLab Burning Board" >< r) && ("Invalid SQL: SELECT * FROM" >< r)) {
      security_message(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}

