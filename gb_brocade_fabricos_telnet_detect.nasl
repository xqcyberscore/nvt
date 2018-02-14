###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_brocade_fabricos_telnet_detect.nasl 8777 2018-02-13 07:55:44Z cfischer $
#
# Brocade Fabric OS Detection (Telnet)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140765");
  script_version("$Revision: 8777 $");
  script_tag(name: "last_modification", value: "$Date: 2018-02-13 08:55:44 +0100 (Tue, 13 Feb 2018) $");
  script_tag(name: "creation_date", value: "2018-02-12 16:06:34 +0700 (Mon, 12 Feb 2018)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brocade Fabric OS Detection (Telnet)");

  script_tag(name: "summary" , value: "Detection of Brocade Fabric OS.

The script sends a telnet connection request to the device and attempts to detect the presence of devices running 
Fabric OS and to extract its version.");
  
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  script_xref(name: "URL", value: "http://www.brocade.com/en/products-services/storage-networking/fibre-channel.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("telnet_func.inc");

port = get_telnet_port(default: 23);

banner = get_telnet_banner(port: port);

if ("Fabric OS" >< banner) {
  version = "unknown";

  # Fabric OS (tm)  Release v3.1.0
  vers = eregmatch(pattern: "(Fabos Version |Fabric OS.*Release v)([0-9a-z.]+)", string: banner);
  if (!isnull(vers[2]))
    version = vers[2];

  set_kb_item(name: "brocade_fabricos/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/o:brocade:fabric_os:");
  if (!cpe)
    cpe = 'cpe:/o:brocade:fabric_os';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: "telnet");
  register_and_report_os(os: "Brocade Fabric OS", version: version, cpe: cpe, banner_type: "Telnet banner",
                         port: port, banner: banner, desc: "Brocade Fabric OS Detection (Telnet)",
                         runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Brocade Fabric OS", version: version, install: port + '/tcp',
                                           cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
