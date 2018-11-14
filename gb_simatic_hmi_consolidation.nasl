###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_hmi_consolidation.nasl 12344 2018-11-14 09:58:21Z ckuersteiner $
#
# Siemens SIMATIC HMI Device Detection Consolidation
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141684");
  script_version("$Revision: 12344 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-14 10:58:21 +0100 (Wed, 14 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-14 15:35:48 +0700 (Wed, 14 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC HMI Device Detection Consolidation");

  script_tag(name:"summary", value:"Report the Siemens SIMATIC HMI device model, hardware and firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_simatic_hmi_snmp_detect.nasl", "gb_simatic_hmi_http_detect.nasl");
  script_mandatory_keys("simatic_hmi/detected");

  script_xref(name:"URL", value:"https://www.siemens.com/global/en/home/products/automation/simatic-hmi.html");

  exit(0);
}

include("host_details.inc");

if (!get_kb_item("simatic_hmi/detected"))
  exit(0);

detected_version = "unknown";
detected_model   = "unknown";

# Version
foreach source (make_list("http", "snmp")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("simatic_hmi/" + source + "/*/version");
  foreach version (version_list) {
    if (version && version != "unknown") {
      detected_version = version;
      set_kb_item(name: "simatic_hmi/version", value: version);
    }
  }
}

# Model
foreach source (make_list("http", "snmp")) {
  if (detected_model != "unknown")
    break;

  model_list = get_kb_list("simatic_hmi/" + source + "/*/model");
  foreach model (model_list) {
    if (model && model != "unknown") {
      detected_model = model;
      set_kb_item(name: "simatic_hmi/model", value: model);
    }
  }
}

app_name = "Siemens SIMATIC HMI ";
if (detected_model != "unknown")
  app_name += detected_model;

app_cpe = 'cpe:/a:siemens:simatic_hmi';
os_cpe = 'cpe:/o:siemens:simatic_hmi';

# SNMP
if (snmp_ports = get_kb_list("simatic_hmi/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    hw_version = get_kb_item("simatic_hmi/snmp/" + port + "/hw_version");
    if (hw_version) {
      extra += '  HW Version:     ' + hw_version + '\n';
      replace_kb_item(name: "simatic_hmi/hw_version", value: hw_version);
    }

    register_product(cpe: app_cpe, location: port + '/tcp', port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: port + '/tcp', port: port, service: "snmp", proto: "udp");
  }
}

# HTTP
if (http_ports = get_kb_list("simatic_hmi/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    register_product(cpe: app_cpe, location: '/', port: port, service: "www");
    register_product(cpe: os_cpe, location: '/', port: port, service: "www");
  }
}


os_name = "Siemens SIMATIC HMI Firmware";

register_and_report_os(os: os_name, version: detected_version, cpe: os_cpe,
                       desc: "Siemens SIMATIC HMI Device Detection Consolidation", runs_key: "unixoide");

report  = build_detection_report(app: app_name, version: detected_version,
                                 install: "/", cpe: app_cpe);
report += '\n\n';
report += build_detection_report(app: os_name, version: detected_version,
                                 install: "/", cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
