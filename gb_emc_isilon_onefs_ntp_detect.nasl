###############################################################################
# OpenVAS Vulnerability Test
#
# EMC Isilon OneFS Devices Detection (NTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.140232");
  script_version("2019-09-24T10:41:39+0000");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-03-31 13:50:07 +0200 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EMC Isilon OneFS Devices Detection (NTP)");

  script_tag(name:"summary", value:"Detection of EMC Isilon OneFS devices

This script performs NTP based detection of EMC Isilon OneFS devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ntp_open.nasl");
  script_require_udp_ports("Services/udp/ntp", 123);
  script_mandatory_keys("ntp/system_banner/available");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_port_for_service(default: 123, ipproto: "udp", proto: "ntp");

if( ! os = get_kb_item("ntp/" + port + "/system_banner") )
  exit( 0 );

if( "Isilon OneFS" >< os ) {
  version = "unknown";

  vers = eregmatch( pattern:"Isilon OneFS/v([0-9.]+)", string:os );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item(name: "emc_isilon_onefs/version", value: version);
  }

  set_kb_item(name: "emc_isilon_onefs/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:emc:isilon_onefs:");
  if (!cpe)
    cpe = 'cpe:/o:emc:isilon_onefs';

  register_product(cpe: cpe, port: port, proto:"udp", service: "ntp");

  log_message(data: build_detection_report(app: "EMC Isilon OneFS", version: version, install: "123/udp",
                                           cpe: cpe, concluded: os),
              port: port, proto: "udp");
  exit(0);
}

exit(0);
