###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_extremeos_snmp_detect.nasl 4642 2016-11-29 07:17:44Z ckuerste $
#
# Extreme ExtremeXOS Detection (SNMP)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106413");
  script_version("$Revision: 4642 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-29 08:17:44 +0100 (Tue, 29 Nov 2016) $");
  script_tag(name:"creation_date", value:"2016-11-25 11:50:20 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Extreme ExtremeXOS Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Extreme ExtremeXOS.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_mandatory_keys("SNMP/sysdesc");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

sysdesc = get_kb_item("SNMP/sysdesc");
if (!sysdesc)
  exit(0);

if ("ExtremeXOS" >< sysdesc) {
  version = "unknown";
  patch = "None";

  mod = eregmatch(pattern: "ExtremeXOS \(([a-zA-Z0-9-]+)", string: sysdesc);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "extremexos/model", value: model);
  set_kb_item(name: "extremexos/detected", value: TRUE);

  vers = eregmatch(pattern: "ExtremeXOS .* version ([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "extremexos/version", value: version);
  }

  p = eregmatch(pattern: "-patch([0-9-]+)", string: sysdesc);
  if (!isnull(p[1])) {
    patch = p[1];
    set_kb_item(name: "extremexos/patch", value: str_replace(string: patch, find: "-", replace: "."));
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:extreme:extremexos:");
  if (!cpe)
    cpe = 'cpe:/a:extreme:extremexos';

  register_product(cpe: cpe);

  log_message(data: build_detection_report(app: "Extreme ExtremeXOS " + model, version: version, cpe: cpe,
                                           install: "161/udp", concluded: vers[0], extra: "Patch: " + patch),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
