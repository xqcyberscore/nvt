###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tika Server Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.810251");
  script_version("2019-08-06T10:10:20+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-06 10:10:20 +0000 (Tue, 06 Aug 2019)");
  script_tag(name:"creation_date", value:"2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)");
  script_name("Apache Tika Server Version Detection");
  script_tag(name:"summary", value:"This script sends an HTTP GET request to figure out
  whether Apache Tika Server is running on the target host, and, if so, which version is installed.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:9998);

url1 = "/";
res1 = http_get_cache(item:url1, port:port);
url2 = "/version";
res2 = http_get_cache(item:url2, port:port);

if((res1 && (res1 =~ "<title>Welcome to the Apache Tika.*Server</title>" || (res1 =~ "Apache Tika.*" && "For endpoints, please see" >< res1))) ||
   res2 && res2 =~ "^HTTP/1\.[01] 200" && egrep(string:res2, pattern:"^Apache Tika ([0-9.]+)", icase:FALSE)) {

  version = "unknown";

  ver = eregmatch(pattern:'<title>Welcome to the Apache Tika ([0-9.]+) Server</title>', string:res1);
  if(ver[1]) {
    version = ver[1];
    conclUrl = report_vuln_url(port:port, url:url1, url_only:TRUE);
  }

  if(version == "unknown") {

    # nb: Sometimes the response was received in "text/plain" without any HTML code
    # matching the title above.
    if(ver = egrep(pattern:"^Apache Tika ([0-9.]+)", string:res1, icase:FALSE)) {
      ver = eregmatch(pattern:"Apache Tika ([0-9.]+)", string:ver);
      if(ver[1]) {
        version = ver[1];
        conclUrl = report_vuln_url(port:port, url:url1, url_only:TRUE);
      }
    }
  }

  if(version == "unknown") {

    req = http_get(item:url2, port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    # nb: Contains a plain:
    # Apache Tika 1.18
    ver = eregmatch(pattern:"^Apache Tika ([0-9.]+)", string:res);
    if(ver[1]) {
      version = ver[1];
      conclUrl = report_vuln_url(port:port, url:url2, url_only:TRUE);
    }
  }

  set_kb_item(name:"Apache/Tika/Server/Installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:tika:");
  if(!cpe)
    cpe = "cpe:/a:apache:tika";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  log_message(data:build_detection_report(app:"Apache Tika Server",
                                          version:version,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:ver[0],
                                          concludedUrl:conclUrl),
              port:port);
}

exit(0);
