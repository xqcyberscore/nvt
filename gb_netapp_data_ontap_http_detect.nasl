###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netapp_data_ontap_http_detect.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# NetApp Data ONTAP Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140348");
  script_version("$Revision: 9608 $");
  script_tag(name: "last_modification", value: "$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name: "creation_date", value: "2017-09-05 08:44:27 +0700 (Tue, 05 Sep 2017)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection (HTTP)");

  script_tag(name: "summary" , value: "Detection of NetApp Data ONTAP.

This script performs HTTP based detection of NetApp Data ONTAP devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("NetApp/banner");
  script_require_ports("Services/www", 80, 443);

  script_xref(name: "URL", value: "http://www.netapp.com/us/products/data-management-software/ontap.aspx");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

banner = get_http_banner(port: port);

if (egrep(pattern: "NetApp/", string: banner)) {
  version = "unknown";

  vers = eregmatch(pattern: "Server: NetApp/(/)?([0-9P.]+)", string: banner);
  if (!isnull(vers[2])) {
    version = vers[2];
    replace_kb_item(name: "netapp_data_ontap/version", value: version);
  }

  set_kb_item(name: "netapp_data_ontap/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9P.]+)", base: "cpe:/o:netapp:data_ontap:");
  if (!cpe)
    cpe = 'cpe:/o:netapp:data_ontap';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "NetApp Data ONTAP", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
