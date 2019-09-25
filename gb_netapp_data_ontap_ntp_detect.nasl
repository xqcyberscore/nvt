###############################################################################
# OpenVAS Vulnerability Test
#
# NetApp Data ONTAP Detection (NTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140347");
  script_version("2019-09-24T10:41:39+0000");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-09-04 15:55:36 +0700 (Mon, 04 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection (NTP)");

  script_tag(name:"summary", value:"Detection of NetApp Data ONTAP.

This script performs NTP based detection of NetApp Data ONTAP devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ntp_open.nasl");
  script_require_udp_ports("Services/udp/ntp", 123);
  script_mandatory_keys("ntp/system_banner/available");

  exit(0);
}

include("misc_func.inc");

port = get_port_for_service(default: 123, ipproto: "udp", proto: "ntp");

if (!os = get_kb_item("ntp/" + port + "/system_banner"))
  exit(0);

if ("Data ONTAP" >< os) {
  set_kb_item(name: "netapp_data_ontap/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/ntp/detected", value: TRUE);
  set_kb_item(name: "netapp_data_ontap/ntp/port", value: port);
  set_kb_item(name: "netapp_data_ontap/ntp/" + port + "/concluded", value: os);

  vers = eregmatch(pattern: "Data ONTAP/([0-9P.]+)", string: os);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "netapp_data_ontap/ntp/" + port + "/version", value: version);
  }
}

exit(0);
