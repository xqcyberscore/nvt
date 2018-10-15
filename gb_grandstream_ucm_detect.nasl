##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grandstream_ucm_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Grandstream UCM Series IP PBX Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106324");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-04 13:39:10 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Grandstream UCM Series IP PBX Detection");

  script_tag(name:"summary", value:"Detection of Grandstream UCM Series IP PBX

The script attempts to identify Grandstream UCM Series IP PBX via SIP banner to extract the model and version
number.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sip_detection.nasl", "find_service.nasl");
  script_mandatory_keys("sip/detected");

  script_xref(name:"URL", value:"http://www.grandstream.com/products/ip-pbxs/ucm-series-ip-pbxs");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("sip.inc");

infos = get_sip_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = get_sip_banner(port: port, proto: proto);

if ("Grandstream UCM" >< banner) {
  version = "unknown";

  mo = eregmatch(pattern: "(UCM[0-9]+)", string: banner);
  if (!isnull(mo[1])) {
    model = mo[1];
    set_kb_item(name: "grandstream_ucm/model", value: model);
  } else {
    model = "unknown_model";
  }

  vers = eregmatch(pattern: "UCM.* ([0-9.]+)", string: banner);
  if (!isnull(vers[1])) {
    version =  vers[1];
    set_kb_item(name: "grandstream_ucm/version", value: version);
  }

  set_kb_item(name: "grandstream_ucm/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:grandstream:" + tolower(model) + ":");
  if (!cpe)
    cpe = 'cpe:/h:grandstream:' + tolower(model);

  location = port + "/" + proto;

  register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );

  log_message(data: build_detection_report(app: "Grandstream " + model, version: version,
                                           install: location, cpe: cpe, concluded: banner),
              port: port, proto: proto);
}

exit(0);
