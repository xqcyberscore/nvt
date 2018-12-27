###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arecont_vision_nvr_detect.nasl 12881 2018-12-25 16:53:59Z tpassfeld $
#
# Arecont Vision NVR Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.114050");
  script_version("$Revision: 12881 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-25 17:53:59 +0100 (Tue, 25 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-21 15:38:32 +0100 (Fri, 21 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Arecont Vision NVR Detection");

  script_tag(name:"summary", value:"Detection of Arecont Vision's IP camera software and their NVR.

  The script sends a connection request to the server and attempts to detect the web interface for Arecont Vision's IP cameras, as well as the NVR model.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://arecontvision.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/";
req = http_get_req(port: port, url: url, add_headers: make_array("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"));
res = http_send_recv(port: port, data: req);

if("content='0; url=ErrBrowserNotSupported.htm'>" >< res) {
  url = "/index.html";
  res = http_get_cache(port: port, item: url);
}

if('var var_brand="Arecont Vision";' >< res || 'alt="Arecont Vision logo" src=' >< res) {
   version = "unknown";
   model = "unknown";
   install = "/";

   #The goal is a response like "</h1>Your client does not have permission to get URL from this server.</body></html>"
   req = http_get_req(port: port, url: "/models/all-cmd.js", add_headers: make_array("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
                                                                                     "Cookie", "Auto=1; Auth=Basic%20YZ%3D"));
   res = http_send_recv(port: port, data: req);

   #WWW-Authenticate: Basic realm="AV800"
   mod = eregmatch(pattern: 'WWW-Authenticate: Basic realm="([A-Za-z]{1,3}[0-9]{1,4})"', string: res);
   if(!isnull(mod[1])) model = mod[1];
   else {
     res = http_get_cache(port: port, item: "/get?model=releasename");
     #model=AV02CMB-100
     mod = eregmatch(pattern: "model=([A-Za-z0-9\-]+)", string: res);
     if(!isnull(mod[1])) model = mod[1];
   }

   conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);
   cpe = "cpe:/h:arecont_vision:nvr:";

   set_kb_item(name: "arecont_vision/nvr/detected", value: TRUE);
   set_kb_item(name: "arecont_vision/nvr/" + port + "/detected", value: TRUE);
   set_kb_item(name: "arecont_vision/nvr/model", value: model);

   register_and_report_cpe(app: "Arecont Vision NVR",
                           ver: version,
                           base: cpe,
                           expr: "^([0-9.]+)",
                           insloc: install,
                           regPort: port,
                           conclUrl: conclUrl,
                           extra: "Model: " + model + ", Version detection requires successful login.");
}

exit(0);
