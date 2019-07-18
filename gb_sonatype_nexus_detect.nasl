###############################################################################
# OpenVAS Vulnerability Test
#
# Sonatype Nexus OSS/Pro Version Detection
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805324");
  script_version("2019-07-18T06:49:42+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-18 06:49:42 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-01-20 13:00:12 +0530 (Tue, 20 Jan 2015)");
  script_name("Sonatype Nexus OSS/Pro Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of Sonatype Nexus.

  This script sends HTTP GET request and try to get the version from the response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.sonatype.org/nexus/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:8081);

banner = get_http_banner(port:port);

if(banner && "erver: Nexus" >< banner) {
  version = "unknown";

  # Server: Nexus/3.0.2-02 (OSS)
  # Server: Nexus/3.17.0-01 (OSS)
  # Server: Nexus/2.14.1-01
  vers = eregmatch(pattern:"Server: Nexus.([0-9.]+(-[0-9]+)?)", string:banner, icase:TRUE);
  if(!isnull(vers[1])) {
    version = vers[1];
    install = "/";
  }

  set_kb_item(name:"nexus/installed",value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:sonatype:nexus:");
  if(!cpe)
    cpe = "cpe:/a:sonatype:nexus";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Sonatype Nexus", version:version, install:install, cpe:cpe,
                                          concluded:vers[0]),
              port:port);
  exit(0);
}

foreach dir (make_list_unique("/", "/nexus",  cgi_dirs(port:port))) {
  install = dir;
  if(dir == "/") dir = "";

  ## if version is not available in banner request for '/#welcome' page
  url = dir + "/#welcome";
  res = http_get_cache(item:url, port:port);

  if(res && (">Sonatype Nexus<" >< res || ">Sonatype Nexus Professional<" >< res)) {
    version = "unknown";
    found = TRUE;
    conclurl = url;

    vers = eregmatch(pattern:"verssion=([0-9.]+(-[0-9]+)?)", string:res);
    if(!isnull(vers[1]))
      version = vers[1];
  } else {
    url = dir + "/#browse/welcome";
    res = http_get_cache(item:url, port:port);

    if("Nexus Repository Manager" >< res) {
      version = "unknown";
      found = TRUE;
      conclurl = url;

      # loading-prod.css?_v=3.15.2-01">
      vers = eregmatch(pattern:"_v=([0-9.-]+)", string:res);
      if(!isnull(vers[1]))
        version = vers[1];
    }
  }

  if(found) {

    set_kb_item(name:"nexus/installed",value:TRUE);

    cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/a:sonatype:nexus:");
    if(!cpe)
      cpe = "cpe:/a:sonatype:nexus";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Sonatype Nexus", version:version, install:install, cpe:cpe,
                                            concluded:vers[0], concludedUrl:conclurl),
                port:port);
    exit(0);
  }
}

exit(0);
