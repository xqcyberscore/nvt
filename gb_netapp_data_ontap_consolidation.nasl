###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netapp_data_ontap_consolidation.nasl 13280 2019-01-25 07:45:24Z ckuersteiner $
#
# NetApp Data ONTAP Detection Consolidation
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.141923");
  script_version("$Revision: 13280 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-25 08:45:24 +0100 (Fri, 25 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-25 12:54:35 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection Consolidation");

  script_tag(name:"summary", value:"The script reports a detected NetApp Data ONTAP including the version
number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_netapp_data_ontap_http_detect.nasl", "gb_netapp_data_ontap_ntp_detect.nasl",
                      "gb_netapp_data_ontap_snmp_detect.nasl");
  script_mandatory_keys("netapp_data_ontap/detected");

  script_xref(name:"URL", value:"http://www.netapp.com/us/products/data-management-software/ontap.asp");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("netapp_data_ontap/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("http", "ntp", "snmp")) {
  version_list = get_kb_list("netapp_data_ontap/" + source + "/*/version");
  foreach vers (version_list) {
    if (vers != "unknown" && detected_version == "unknown")
      detected_version = vers;
  }
}

cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9p.]+)", base: "cpe:/o:netapp:data_ontap:");
if (!cpe)
  cpe = 'cpe:/o:netapp:data_ontap';

if (http_ports = get_kb_list("netapp_data_ontap/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    register_product(cpe: cpe, location: '/', port: port, service: "www");
  }
}

if (ntp_ports = get_kb_list("netapp_data_ontap/ntp/port")) {
  foreach port (ntp_ports) {
    extra += 'NTP on port ' + port + '/udp\n';

    register_product(cpe: cpe, location: '/', port: port, service: "ntp", proto: "udp");
  }
}

if (snmp_ports = get_kb_list("netapp_data_ontap/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    register_product(cpe: cpe, location: '/', port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: "NetApp Data ONTAP", version: detected_version, cpe: cpe, install: "/");

if (extra) {
  report += '\nDetection methods:\n';
  report += '\r\n' + extra;
}

if (report)
  log_message(port: 0, data: report);

exit(0);
