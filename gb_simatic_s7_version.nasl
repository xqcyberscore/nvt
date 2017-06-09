###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_version.nasl 6160 2017-05-18 09:39:36Z ckuerste $
#
# Siemens SIMATIC S7 Device Version
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
 script_oid("1.3.6.1.4.1.25623.1.0.106096");
 script_version ("$Revision: 6160 $");
 script_tag(name: "last_modification", value: "$Date: 2017-05-18 11:39:36 +0200 (Thu, 18 May 2017) $");
 script_tag(name: "creation_date", value: "2016-06-15 15:30:33 +0700 (Wed, 15 Jun 2016)");
 script_tag(name: "cvss_base", value: "0.0");
 script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

 script_tag(name: "qod_type", value: "remote_active");

 script_name("Siemens SIMATIC S7 Device Version");

 script_tag(name: "summary" , value: "Report the Siemens SIMATIC S7 device model and firmaware version");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("gb_simatic_s7_cotp_detect.nasl", "gb_simatic_s7_snmp_detect.nasl", "gb_simatic_s7_http_detect.nasl");
 script_mandatory_keys("simatic_s7/detected");



 exit(0);
}

include("host_details.inc");
include("cpe.inc");

if (model = get_kb_item("simatic_s7/cotp/model")) {
  source = "cotp";
  proto = "tcp";
}
else
  if (model = get_kb_item("simatic_s7/snmp/model")) {
    source = "snmp";
    proto = "udp";
  }
  else 
    if (model = get_kb_item("simatic_s7/http/model")) {
      source = "http";
      proto = "tcp";
    }

if (!model)
  exit(0);
  
set_kb_item(name: "simatic_s7/model", value: model);

if (version = get_kb_item("simatic_s7/" + source + "/version")) {
  set_kb_item(name: "simatic_s7/version", value: version);
}

cpe_model = tolower(ereg_replace(pattern: "[ /]", string: model, replace: "_"));
cpe = build_cpe(value: version, exp:"([0-9.]+)", base: 'cpe:/a:siemens:simatic_s7_' + cpe_model + ':');
if (isnull(cpe))
  cpe = 'cpe:/a:siemens:simatic_s7_' + cpe_model;

port = get_kb_item("simatic_s7/" + source + "/port");

register_product(cpe: cpe, location: source, port: port);

log_message(data: build_detection_report(app: "Siemens SIMATIC S7-" + model, version: version,
                                         install: source, cpe: cpe),
            port: port, proto: proto);

exit(0);

