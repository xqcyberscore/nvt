###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_detect.nasl 5888 2017-04-07 09:01:53Z teissa $
#
# dotCMS Detection
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
 script_oid("1.3.6.1.4.1.25623.1.0.106114");
 script_version ("$Revision: 5888 $");
 script_tag(name: "last_modification", value: "$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
 script_tag(name: "creation_date", value: "2016-07-05 08:55:18 +0700 (Tue, 05 Jul 2016)");
 script_tag(name: "cvss_base", value: "0.0");
 script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

 script_tag(name: "qod_type", value: "remote_banner");

 script_name("dotCMS Detection");

 script_tag(name: "summary" , value: "Detection of dotCMS

The script sends a connection request to the server and attempts to detect the presence of dotCMS and to
extract its version");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_xref(name: "URL", value: "http://dotcms.com");


 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/", "/dotcms", "/dotCMS", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/html/portal/login.jsp";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("<title>dotCMS : Enterprise Web Content Management</title>" >< res && "modulePaths: { dotcms:" >< res) {
    version  = "unknown";
    
    ver = eregmatch(pattern: "<br />.*(COMMUNITY|ENTERPRISE) EDITION.*(([0-9.]){5})|(([0-9.]){3})<br/>",
                    string: res);
    if (!isnull(ver[4]))
      version = ver[4];
    else if (!isnull(ver[2]))
      version = ver[2];

    set_kb_item(name: "dotCMS/installed", value: TRUE);
    if (version != "unknown")
      set_kb_item(name: "dotCMS/version", value: version);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dotcms:dotcms:");
    if (isnull(cpe))
      cpe = "cpe:/a:dotcms:dotcms";

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "dotCMS", version: version, install: install, cpe: cpe,
                                             concluded: ver[0]),
                port: port);

    exit(0);
  }
}

exit(0);
