###############################################################################
# OpenVAS Vulnerability Test
#
# Quest DR Series Appliance Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813011");
  script_version("2019-07-03T03:02:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-03 03:02:42 +0000 (Wed, 03 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-03-12 13:08:38 +0530 (Mon, 12 Mar 2018)");

  script_name("Quest DR Series Appliance Remote Detection");

  script_tag(name:"summary", value:"Detection of Quest DR Series Appliance.

  The script sends a connection request to the server and attempts to detect the
  presence of Quest DR Series Appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ('ng-app="drConsoleApp' >< res && '<dr-masthead-application-name>' >< res) {
  version = "unknown";

  data = '{"jsonrpc":"2.0","method":"getPreLoginInfo","params":{"classname":"DRPreLoginAccess"},"id":1}';

  url = "/ws/v1.0/jsonrpc";

  headers = make_array("Content-Type", "application/json-rpc");

  req = http_post_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # "jsonrpc":"2.0","id":1,"result":{"keys":["CreationClassName","ServiceID"],"objects":[{"fqdn":"dell-storage.example.com","reset_option":"no","ip_addr":"1.1.1.1","service_tag":"993Y8F2","version":"4.0.0273.0 ","hostname":"dell-storage","ServiceID":"DL6000-test","CreationClassName":"DRPreLoginAccess","product_name":"Dell DR6300"}]}}
  vers = eregmatch(pattern: '"version":"([0-9a-z.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  mod = eregmatch(pattern: '"product_name":"([^ ]+ )?([^"]+)', string: res);
  if (!isnull(mod[2]))
    model = mod[2];

  set_kb_item(name:"quest/dr/appliance/detected", value:TRUE);

  if (model) {
    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:quest:" + tolower(model) + ":");
    if (!cpe)
      cpe = 'cpe:/a:quest:' + tolower(model);
  } else {
    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:quest:disk_backup:");
    if (!cpe)
      cpe = 'cpe:/a:quest:disk_backup';
  }

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Quest DR Series " + model, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0) ;
}

exit(0);
