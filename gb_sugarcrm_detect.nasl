###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sugarcrm_detect.nasl 4109 2016-09-19 10:35:59Z mime $
#
# SugarCRM Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.106122");
 script_version ("$Revision: 4109 $");
 script_tag(name: "last_modification", value: "$Date: 2016-09-19 12:35:59 +0200 (Mon, 19 Sep 2016) $");
 script_tag(name: "creation_date", value: "2016-07-08 14:44:45 +0700 (Fri, 08 Jul 2016)");
 script_tag(name: "cvss_base", value: "0.0");
 script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

 script_tag(name: "qod_type", value: "remote_banner");

 script_name("SugarCRM Detection");

 script_tag(name: "summary" , value: "Detection of SugarCRM

The script sends a connection request to the server and attempts to detect the presence of SugarCRM and to
extract its version");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_xref(name: "URL", value: "https://www.sugarcrm.com/");

 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/sugarcrm", "/SugarCRM", "/sugar", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php?action=Login&module=Users&login_module=Home&login_action=index";
  res = http_get_cache(port: port, item: url);

  if (res =~ "<title>(.*)SugarCRM</title>" && ("alt='Powered By SugarCRM'>" >< res || "Set-Cookie: sugar_user_them" >< res )) {
    version = "unknown";

    req = http_get(port: port, item: dir + "/sugar_version.json");
    res = http_keepalive_send_recv(port: port, data: req);
    ver = eregmatch(pattern: '"sugar_version": "([0-9.]+)",', string: res);
    if (!isnull(ver[1]))
      version = ver[1];

    set_kb_item(name: "sugarcrm/installed", value: TRUE);
    if (version != "unknown")
      set_kb_item(name: "www/" + port + "/sugarcrm", value: version);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sugarcrm:sugarcrm:");
    if (isnull(cpe))
      cpe = "cpe:/a:sugarcrm:sugarcrm";

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "SugarCRM", version: version, install: install,
                                             cpe: cpe, concluded: ver[0]),
                port: port);
  }
}

exit(0);
