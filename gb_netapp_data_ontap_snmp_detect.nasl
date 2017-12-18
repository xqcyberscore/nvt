###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netapp_data_ontap_snmp_detect.nasl 8142 2017-12-15 13:00:23Z cfischer $
#
# NetApp Data ONTAP Detection (SNMP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140349");
  script_version("$Revision: 8142 $");
  script_tag(name: "last_modification", value: "$Date: 2017-12-15 14:00:23 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name: "creation_date", value: "2017-09-05 09:15:15 +0700 (Tue, 05 Sep 2017)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection (SNMP)");

  script_tag(name: "summary" , value: "Detection of NetApp Data ONTAP.

This script performs SNMP based detection of NetApp Data ONTAP devices.");
  
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_xref(name: "URL", value: "http://www.netapp.com/us/products/data-management-software/ontap.aspx");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

if (sysdesc =~ "^NetApp Release") {
  version = "unknown";

  vers = eregmatch(pattern: "NetApp Release ([0-9P.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    version = vers[1];
    replace_kb_item(name: "netapp_data_ontap/version", value: version);
  }

  set_kb_item(name: "netapp_data_ontap/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9P.]+)", base: "cpe:/o:netapp:data_ontap:");
  if (!cpe)
    cpe = 'cpe:/o:netapp:data_ontap';

  register_product(cpe: cpe, port: port, location: port + "/udp", proto: "udp", service: "snmp");

  log_message(data: build_detection_report(app: "NetApp Data ONTAP", version: version, install: port + "/udp",
                                           cpe: cpe, concluded: sysdesc),
              port: port, proto: 'udp');
  exit(0);
}

exit(0);
