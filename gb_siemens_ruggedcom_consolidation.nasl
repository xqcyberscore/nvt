###############################################################################
# OpenVAS Vulnerability Test
#
# Siemens RUGGEDCOM / Rugged Operating System Detection Consolidation
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140811");
  script_version("2019-10-10T10:10:04+0000");
  script_tag(name:"last_modification", value:"2019-10-10 10:10:04 +0000 (Thu, 10 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-02-26 14:49:15 +0700 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens RUGGEDCOM / Rugged Operating System Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected Siemens RUGGEDCOM device and the
  and the Rugged Operating System including the version number and exposed services.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_siemens_ruggedcom_snmp_detect.nasl", "gb_siemens_ruggedcom_telnet_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_siemens_ruggedcom_http_detect.nasl");
  script_mandatory_keys("siemens_ruggedcom/detected");

  script_xref(name:"URL", value:"http://w3.siemens.com/mcms/industrial-communication/en/rugged-communication/pages/ruggedcom.aspx");

  exit(0);
}

include("host_details.inc");

if (!get_kb_item("siemens_ruggedcom/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "unknown";

# Version
foreach source (make_list("telnet", "snmp", "http")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("siemens_ruggedcom/" + source + "/*/version");
  foreach version (version_list) {
    if (version) {
      detected_version = version;
      set_kb_item(name: "siemens_ruggedcom/version", value: version);
    }
  }
}

# Model
foreach source (make_list("telnet", "snmp", "http")) {
  if (detected_model != "unknown")
    break;

  model_list = get_kb_list("siemens_ruggedcom/" + source + "/*/model");
  foreach model (model_list) {
    if (model) {
      detected_model = model;
      set_kb_item(name: "siemens_ruggedcom/model", value: model);
    }
  }
}

if (detected_version != "unknown") {
  os_cpe  = "cpe:/o:siemens:ruggedcom_rugged_operating_system:" + detected_version;
  os_legacy_cpe = "cpe:/o:ruggedcom:ros:" + detected_version;
  os_name = "Siemens Rugged Operating System " + detected_version;
} else {
  os_cpe  = "cpe:/o:siemens:ruggedcom_rugged_operating_system";
  os_legacy_cpe = "cpe:/o:ruggedcom:ros";
  os_name = "Siemens Rugged Operating System";
}

if (detected_model != "unknown") {
  cpe_model = str_replace(string: tolower(detected_model), find: "-", replace: "_");
  hw_cpe  = "cpe:/h:siemens:ruggedcom_" + cpe_model;
  hw_name = "Siemens RUGGEDCOM " + detected_model;
} else {
  hw_cpe  = "cpe:/h:siemens:ruggedcom_unknown_model";
  hw_name = "Siemens RUGGEDCOM Unknown Model";
}

register_and_report_os(os: os_name, cpe: os_cpe, desc: "Siemens RUGGEDCOM / Rugged Operating System Detection Consolidation", runs_key: "unixoide");

location = "/";

if (telnet_ports = get_kb_list("siemens_ruggedcom/telnet/port")) {
  foreach port (telnet_ports) {
    concluded = get_kb_item("siemens_ruggedcom/telnet/" + port + "/concluded");
    extra += '\nTelnet on port ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded:   ' + concluded + '\n';

    mac = get_kb_item("siemens_ruggedcom/telnet/" + port + "/mac");
    if (mac)
      extra += '  MAC Address: ' + mac + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: os_legacy_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

if (snmp_ports = get_kb_list("siemens_ruggedcom/snmp/port")) {
  foreach port (snmp_ports) {
    concluded = get_kb_item("siemens_ruggedcom/snmp/" + port + "/concluded");
    concludedOID = get_kb_item("siemens_ruggedcom/snmp/" + port + "/concludedOID");
    extra += '\nSNMP on port ' + port + '/udp\n';
    if (concluded) {
      extra += '  Concluded from   ' + concluded;
      if (concludedOID)
        extra += ' via OID: ' + concludedOID + '\n';
      else
        extra += '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_legacy_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("siemens_ruggedcom/http/port")) {
  foreach port (http_ports) {
    concluded = get_kb_item("siemens_ruggedcom/http/" + port + "/concluded");
    extra += '\nHTTP(s) on port ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded:   ' + concluded + '\n';

    mac = get_kb_item("siemens_ruggedcom/http/" + port + "/mac");
    if (mac)
      extra += '  MAC Address: ' + mac + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_legacy_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: os_name, version: detected_version,
                                install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE,
                                 install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

log_message(port: 0, data: report);

exit(0);
