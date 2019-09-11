###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios Log Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.107058");
  script_version("2019-09-10T09:51:06+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-09-10 09:51:06 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"creation_date", value:"2016-10-12 13:26:09 +0700 (Wed, 12 Oct 2016)");

  script_name("Nagios Log Server Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Nagios Log Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-log-server/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/nagioslogserver", "/nagios", cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/login";
  buf = http_get_cache(port:port, item:url);

  if (buf && buf =~ "^HTTP/1\.[01] 200" && "Nagios Log Server" >< buf && "Nagios Enterprises" >< buf
      && "var LS_USER_ID" >< buf &&
      ('<div class="demosplash"></div>' >< buf || '<div class="loginsplash"></div>' >< buf)) {

    set_kb_item(name:"nagios/log_server/detected", value:TRUE);

    if ('<div class="demosplash"></div>' >< buf)
      extra = "Demo Version";

    version = "unknown";

    vers = eregmatch(string:buf, pattern:'var LS_VERSION = "([0-9.]+)"', icase:TRUE);

    # var LS_VERSION = "2.0.7";
    if (isnull(vers[1]))
      vers = eregmatch(string:buf, pattern:'ver=([0-9.]+)">');

    if (!isnull(vers[1]))
      version = vers[1];

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:nagios:log_server:");
    if (!cpe)
      cpe = 'cpe:/a:nagios:log_server';

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Nagios Log Server", version:version, install:install, cpe:cpe,
                                            concluded:vers[0], extra:extra),
                port:port);
  }
}

exit(0);
