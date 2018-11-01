###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jquery_detect.nasl 12178 2018-11-01 03:02:12Z ckuersteiner $
#
# jQuery Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141622");
  script_version("$Revision: 12178 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-01 04:02:12 +0100 (Thu, 01 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-01 09:53:59 +0700 (Thu, 01 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("jQuery Detection");

  script_tag(name:"summary", value:"Detection of jQuery.

The script sends a connection request to the server and attempts to detect jQuery and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://jquery.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

detect = eregmatch(pattern: 'src=["\']([^ ]+)(jquery([0-9.-]+)?(\\.(min|slim|slim\\.min)?)\\.js)', string: res);
version = "unknown";
location = "/";

if (detect[1] =~ "^http")
  exit(0);	# hosted on another server

# src="js/jquery-1.8.2.min.js"
if (!isnull(detect[3])) {
  vers = eregmatch(pattern: "([0-9.]+)", string: detect[3]);
  if (!isnull(vers[1]))
    version = vers[1];

  if (!isnull(detect[1]))
    location += ereg_replace(string: detect[1], pattern: "^(/)?(.*)/$", replace: "\2");

  set_kb_item(name: "jquery/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jquery:jquery:");
  if (!cpe)
    cpe = 'cpe:/a:jquery:jquery';

  register_product(cpe: cpe, location: location, port: port);

  log_message(data: build_detection_report(app: "jQuery", version: version, install: location, cpe: cpe,
                                           concluded: detect[0]),
              port: port);
  exit(0);
}
# src="/imports/jquery/dist/jquery.slim.min.js"
# src="scripts/jquery.min.js"
else if (!isnull(detect[2])) {
  url = detect[1] + detect[2];
  if (url !~ "^/")
    url = "/" + url;

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # /*! jQuery v1.9.1 | (c) 2005, 2012 jQuery Foundation, Inc. | jquery.org/license
  vers = eregmatch(pattern: "jQuery v([0-9.]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  if (!isnull(detect[1]))
    location += ereg_replace(string: detect[1], pattern: "^(/)?(.*)/$", replace: "\2");

  set_kb_item(name: "jquery/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:jquery:jquery:");
  if (!cpe)
    cpe = 'cpe:/a:jquery:jquery';

  register_product(cpe: cpe, location: location, port: port);

  log_message(data: build_detection_report(app: "jQuery", version: version, install: location, cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
