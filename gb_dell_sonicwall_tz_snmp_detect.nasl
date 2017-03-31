###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_tz_snmp_detect.nasl 5208 2017-02-06 10:00:07Z ckuerste $
#
# Dell SonicWALL TZ Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.106569");
  script_version("$Revision: 5208 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-06 11:00:07 +0100 (Mon, 06 Feb 2017) $");
  script_tag(name:"creation_date", value:"2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell SonicWALL TZ Detection");

  script_tag(name:"summary", value:"Detection of Dell SonicWALL TZ

This script performs SNMP based detection of Dell SonicWALL TZ devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

port = get_kb_item("Services/udp/snmp");
if (!port)
  port = 161;

sysdesc = get_kb_item("SNMP/sysdesc");
if (!sysdesc)
  exit(0);

if ("SonicWALL TZ" >< sysdesc) {
  version = "unknown";

  mod = eregmatch(pattern: "SonicWALL TZ ([0-9]+)", string: sysdesc);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "sonicwall/tz/model", value: model);

  vers = eregmatch(pattern: "SonicOS Enhanced ([^)]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version =  vers[1];
    set_kb_item(name: "sonicwall/tz/version", value: version);
  }

  set_kb_item(name: "sonicwall/tz/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.-]+)",
                  base: "cpe:/a:dell:sonicwall_totalsecure_tz_" + model + "_firmware:");
  if (!cpe)
    cpe = 'cpe:/a:dell:sonicwall_totalsecure_tz_' + model + "_firmware";

  register_product(cpe: cpe, port: port, service: "snmp");

  log_message(data: build_detection_report(app: "Dell SonicWALL TZ " + model, version: version,
                                           install: port + "/udp", cpe: cpe, concluded: sysdesc),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
