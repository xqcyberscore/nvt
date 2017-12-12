###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hirschmann_webui_detect.nasl 8077 2017-12-11 14:15:34Z cfischer $
#
# Hirschmann Devices Detection (Web UI)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140575");
  script_version("$Revision: 8077 $");
  script_tag(name: "last_modification", value: "$Date: 2017-12-11 15:15:34 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name: "creation_date", value: "2017-12-04 14:40:12 +0700 (Mon, 04 Dec 2017)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Hirschmann Devices Detection (Web UI)");

  script_tag(name: "summary" , value: "Detection of Hirschmann devices over HTTP.

The script sends a connection request to the server and attempts to detect Hirschmann devices and to extract
its version.");
  
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name: "URL", value: "http://www.hirschmann.com/en/Hirschmann_Produkte/index.phtml");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);
res = http_get_cache(port: port, item: "/");

if (res =~ "^HTTP/1\.[01] 200" &&
     ('VALUE="com.hirschmann.' >< res && 'productName' >< res) ||
     ("img/hirschLogo.gif" >< res && "GAI.SESSIONID" >< res)) {

  set_kb_item( name:"hirschmann_device/detected", value:TRUE );
  set_kb_item( name:"hirschmann_device/http/detected", value:TRUE );
  set_kb_item( name:"hirschmann_device/http/port", value:port );

  fw_version      = "unknown";
  product_name    = "unknown";
  model_shortname = "unknown";

  prod_name = eregmatch(pattern: '"productName" VALUE="([^"]+)', string: res);
  if (isnull(prod_name[1])) {
    prod_name = eregmatch(pattern: "<title>([^<]+)", string: res);
    if (!isnull(prod_name[1]))
      product_name = prod_name[1];
      concluded += prod_name[0] + '\n';
  } else {
    product_name = prod_name[1];
    concluded += prod_name[0] + '\n';
  }

  vers = eregmatch(pattern: '"productVersion" VALUE="([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    fw_version = vers[1];
    concluded += vers[0] + '\n';
  }

  set_kb_item(name: "hirschmann_device/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "hirschmann_device/http/" + port + "/product_name", value: product_name);
  set_kb_item(name: "hirschmann_device/http/" + port + "/model_shortname", value: model_shortname);

  if (concluded)
    set_kb_item(name: "hirschmann_device/http/" + port + "/concluded", value: concluded);
}

exit(0);
