###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rockwell_micrologix_http_detect.nasl 8350 2018-01-10 05:26:32Z ckuersteiner $
#
# Rockwell Automation MicroLogix Detection (http)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140662");
  script_version("$Revision: 8350 $");
  script_tag(name: "last_modification", value: "$Date: 2018-01-10 06:26:32 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name: "creation_date", value: "2018-01-10 10:09:48 +0700 (Wed, 10 Jan 2018)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name: "qod_type", value: "remote_banner");

  script_name("Rockwell Automation MicroLogix Detection (http)");

  script_tag(name: "summary" , value: "Detection of Rockwell Automation MicroLogix PLC's.

The script sends a connection request to the server and attempts to detect Rockwell Automation MicroLogix PLC's and
extract its version.");
  
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ABwww/banner");

  script_xref(name: "URL", value: "http://ab.rockwellautomation.com/Programmable-Controllers/MicroLogix-Systems");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);
if ("A-B WWW" >!< banner)
  exit(0);

url = "/home.htm";
res = http_get_cache(port: port, item: url);

if ("<title>Rockwell Automation</title>" >< res && res =~ "MicroLogix [0-9]+ Processor") {
  app = eregmatch(pattern: "MicroLogix ([0-9]+) Processor", string: res);
  device = app[1];
  app = app[0];
  version = "unknown";

  vers = eregmatch(pattern: "O(/)?S.*Revision</td><td>Series ([A-Z]) FRN ([0-9.]+)</td>", string: res);
  if (!isnull(vers[3]))
    version = vers[3];

  if (!isnull(vers[2])) {
    series = vers[2];
    set_kb_item(name: "rockwell_micrologix/series", value: series);
  }

  dev_name = eregmatch(pattern: "Device Name</td><td>([^<]+)", string: res);
  if (!isnull(dev_name[1])) {
    dev_name = dev_name[1];
    set_kb_item(name: "rockwell_micrologix/device_name", value: dev_name);
    extra = 'Device Name:   ' + dev_name + '\n';
  }

  mac = eregmatch(pattern: "Ethernet Address \(MAC\)</td><td>([A-F0-9-]{17})", string: res);
  if (!isnull(mac[1])) {
    mac = str_replace( string: mac[1], find: "-", replace: ":");
    extra += 'Mac Address:   ' + mac + '\n';
    register_host_detail(name: "MAC", value: mac, desc: "gb_linksys_wvbro25_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac);
  }

  set_kb_item(name: "rockwell_micrologix/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)",
                  base: "cpe:/o:rockwellautomation:micrologix_" + device + "_firmware:");
  if (!cpe)
    cpe = 'cpe:/o:rockwellautomation:micrologix_' + device + '_firmware';

  register_product(cpe: cpe, location: "/", port: port, service: "www");
  register_and_report_os(os: "Rockwell Automation MicroLogix Controller", cpe: cpe, banner_type: "HTTP page",
                         port: port, desc: "Rockwell Automation MicroLogix Detection (http)");

  log_message(data: build_detection_report(app: app, version: version, install: "/", cpe: cpe, concluded: vers[0],
                                           concludedUrl: url, extra: extra),
              port: port);
  exit(0);
}

exit(0);
