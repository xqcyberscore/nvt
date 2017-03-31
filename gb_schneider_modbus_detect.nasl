###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_modbus_detect.nasl 5250 2017-02-09 10:51:30Z ckuerste $
#
# Schneider Electric Devices Detection (modbus)
#
# Authors:
# INCIBE <ics-team@incibe.es>
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
  script_oid("1.3.6.1.4.1.25623.1.0.106542");
  script_version("$Revision: 5250 $");
  script_tag(name:"last_modification", value: "$Date: 2017-02-09 11:51:30 +0100 (Thu, 09 Feb 2017) $");
  script_tag(name:"creation_date", value: "2017-01-26 10:19:28 +0700 (Thu, 26 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Schneider Electric Devices Detection (modbus)");

  script_tag(name:"summary", value:"Detection of Schneider Electric Devices over Modbus.

Tries to detect Schneider Electric devices over the Modbus protocol.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_modbus_detect.nasl");
  script_mandatory_keys("modbus/vendor", "modbus/prod_code");
  script_require_ports(502);

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

port = 502;

vendor = get_kb_item("modbus/vendor");
if (!vendor || "Schneider Electric" >!< vendor)
  exit(0);

prod = get_kb_item("modbus/prod_code");
if (!prod)
  exit(0);
else {
  set_kb_item(name: "schneider_electric/product", value: prod);
  cpe_prod = tolower(ereg_replace(pattern: " ", string: prod, replace: ""));
}

version = 'unknown';
vers = get_kb_item("modbus/version");
vers = eregmatch(pattern: "(v|V)([0-9.]+)", string: vers);
if (!isnull(vers[2])) {
  version = vers[2];
  set_kb_item(name: "schneider_electric/version", value: version);
}

set_kb_item(name: "schneider_electric/detected", value: TRUE);

# Try to get some additional information over modbus
if (get_port_state(502) && sock = open_sock_tcp(port)) {
  # CPU module
  req = raw_string(0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x5a, 0x00, 0x02);
  send(socket: sock, data: req, length: strlen(req));
  res = recv(socket: sock, length: 1024, timeout: 1);

  if (res && strlen(res) > 33) {
    length = ord(res[32]);
    cpu_module = chomp(substr(res, 33, 32 + length));
    report = "CPU Module:   " + cpu_module + "\n";
  }

  # Memory Card
  req = raw_string(0x01, 0xbf, 0x00, 0x00, 0x00, 0x05, 0x00, 0x5a, 0x00, 0x06, 0x06);
  send(socket: sock, data: req, length: strlen(req));
  res = recv(socket: sock, length: 1024, timeout: 1);

  if (res && strlen(res) > 17) {
    length = ord(res[16]);
    mem_card = chomp(substr(res, 17, 16 + length));
    report += "Memory Card:  " + mem_card + "\n";
  }

  # Project Information
  req = raw_string(0x00, 0x0f, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x5a, 0x00,
                   0x20, 0x00, 0x14, 0x00, 0x64, 0x00, 0x00, 0x00, 0xf6, 0x00);
  send(socket: sock, data: req, length: strlen(req));
  res = recv(socket: sock, length: 1024, timeout: 1);

  if (res && strlen(res) > 169) {
    proj_info = substr(res, 169);
    proj_info = bin2string(ddata: proj_info, nonprint_replace: " ");
    report += "Project Info: " + proj_info;
  }

  close(sock);
}

cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:schneider-electric:" + cpe_prod + ":");
if (!cpe)
  cpe = 'cpe:/h:schneider-electric:' + cpe_prod + ':';

register_product(cpe: cpe, port: port, service: "modbus");
log_message(data: build_detection_report(app: "Schneider Electric " + prod, version: version, install: "502/tcp",
                                         cpe: cpe, concluded: vers[0], extra: report),
            port: 502);

exit(0);
