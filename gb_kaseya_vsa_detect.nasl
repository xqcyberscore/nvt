###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaseya_vsa_detect.nasl 8143 2017-12-15 13:11:11Z cfischer $
#
# Kaseya VSA Detection 
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106738");
  script_version("$Revision: 8143 $");
  script_tag(name: "last_modification", value: "$Date: 2017-12-15 14:11:11 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name: "creation_date", value: "2017-04-10 14:46:29 +0200 (Mon, 10 Apr 2017)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kaseya VSA Detection");

  script_tag(name:"summary", value:"Detection of Kaseya VSA

The script sends a HTTP connection request to the server and attempts to detect the presence of Kaseya VSA and
to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name: "URL", value: "https://www.kaseya.com/products/vsa");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);
if( ! can_host_asp( port:port ) ) exit( 0 );

req = http_get(port: port, item: "/vsapres/web20/core/login.aspx");
res = http_keepalive_send_recv(port: port, data: req);

if ("/themes/default/images/logoforLogin.gif" >< res && "/vsapres/js/kaseya/web/bootstrap.js" >< res &&
    "PoweredByKaseya.png" >< res) {

  version = "unknown";

  vers = eregmatch(pattern: "System Version.*<span>([0-9.]+)</span>", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "kaseya_vsa/version", value: version);
  }

  set_kb_item(name: "kaseya_vas/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:kaseya:virtual_system_administrator:");
  if (!cpe)
    cpe = 'cpe:/a:kaseya:virtual_system_administrator';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Kaseya VSA", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
