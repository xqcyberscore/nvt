###############################################################################
# OpenVAS Vulnerability Test
#
# b2evolution CMS Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.106534");
  script_version("2019-06-06T14:25:19+0000");
  script_tag(name:"last_modification", value:"2019-06-06 14:25:19 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2017-01-20 12:59:58 +0700 (Fri, 20 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("b2evolution Detection");

  script_tag(name:"summary", value:"Detection of b2evolution CMS

  The script sends a HTTP connection request to the server and attempts to detect the presence of b2evolution CMS
  and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://b2evolution.net/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);
if (!can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique( "/", "/b2evolution", cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/") dir = "";

  url1 = dir + "/admin.php";
  url2 = dir + "/blogs/admin.php";
  url3 = dir + "/evoadm.php";
  url4 = dir + "/index.php";
  url5 = dir + "/login.php";
  res1 = http_get_cache(port: port, item: url1);
  res2 = http_get_cache(port: port, item: url2);
  res3 = http_get_cache(port: port, item: url3);
  res4 = http_get_cache(port: port, item: url4);
  res5 = http_get_cache(port: port, item: url5);

  # nb: pwd_salt seems to be removed in newer 6.x versions but pwd_hashed was kept so checking for both.
  # nb2: The "Log into your account seems to be also translateable so checking for a second pattern which seems to be kept in english.
  if (("://b2evolution.net/" >< res1 && ("<title>Log in to your account</title>" >< res1 || "visit b2evolution's website" >< res1) && ("pwd_salt" >< res1 || "pwd_hashed" >< res1)) ||
      ("://b2evolution.net/" >< res2 && ("<title>Log in to your account</title>" >< res2 || "visit b2evolution's website" >< res2) && ("pwd_salt" >< res2 || "pwd_hashed" >< res2)) ||
      ("://b2evolution.net/" >< res3 && ("<title>Log in to your account</title>" >< res3 || "visit b2evolution's website" >< res3) && ("pwd_salt" >< res3 || "pwd_hashed" >< res3)) ||
      'name="generator" content="b2evolution' >< res4 ||
      'name="generator" content="b2evolution' >< res5) {

    version = "unknown";

    # From all admin backend files:
    # <strong>b2evolution 6.11.2-stable</strong>
    # <strong>b2evolution 5.0.8-stable</strong>
    # <strong>b2evolution 4.0.5</strong>
    vers = eregmatch(pattern: "<strong>b2evolution ([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "b2evolution/version", value: version);
      conclUrl = report_vuln_url(port: port, url: url1, url_only: TRUE);
    }

    if (version == "unknown") {
      vers = eregmatch(pattern: "<strong>b2evolution ([0-9.]+)", string: res2);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "b2evolution/version", value: version);
        conclUrl = report_vuln_url(port: port, url: url2, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      vers = eregmatch(pattern: "<strong>b2evolution ([0-9.]+)", string: res3);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "b2evolution/version", value: version);
        conclUrl = report_vuln_url(port: port, url: url3, url_only: TRUE);
      }
    }

    # Both from index.php or login.php:
    # <meta name="generator" content="b2evolution 6.11.2-stable" />
    # <meta name="generator" content="b2evolution 5.0.8-stable" />
    # <meta name="generator" content="b2evolution 4.0.5" />
    if (version == "unknown") {
      vers = eregmatch(pattern: 'content="b2evolution ([0-9.]+)', string: res4);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "b2evolution/version", value: version);
        conclUrl = report_vuln_url(port: port, url: url4, url_only: TRUE);
      }
    }

    if (version == "unknown") {
      vers = eregmatch(pattern: 'content="b2evolution ([0-9.]+)', string: res5);
      if (!isnull(vers[1])) {
        version = vers[1];
        set_kb_item(name: "b2evolution/version", value: version);
        conclUrl = report_vuln_url(port: port, url: url5, url_only: TRUE);
      }
    }

    set_kb_item(name: "b2evolution/installed", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:b2evolution:b2evolution:");
    if (!cpe)
      cpe = 'cpe:/a:b2evolution:b2evolution';

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "b2evolution", version: version, install: install,
                                             cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
