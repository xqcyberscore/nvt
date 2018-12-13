###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logitech_media_server_detect.nasl 12779 2018-12-12 19:14:16Z cfischer $
#
# Logitech SqueezeCenter/Media Server Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811877");
  script_version("$Revision: 12779 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 20:14:16 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2017-10-24 17:24:40 +0530 (Tue, 24 Oct 2017)");
  script_name("Logitech SqueezeCenter/Media Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("LogitechMediaServer/banner");

  script_tag(name:"summary", value:"Detection of Logitech Media Server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:9000);
banner = get_http_banner(port:port);

if(egrep(string:banner, pattern:"^Server: Logitech Media Server", icase:TRUE)) {

  install = port + "/tcp";
  version = "unknown";

  # Server: Logitech Media Server (7.7.2 - 33893)
  ver = eregmatch(pattern:'Server: Logitech Media Server \\(([0-9.]+)[^)]*\\)', string:banner);
  if(ver[1])
    version = ver[1];

  set_kb_item(name:"Logitech/Media/Server/Installed", value:TRUE);
  cpe = build_cpe(value:version, exp:"^([0-9. ]+)", base:"cpe:/a:logitech:media_server:");
  if(!cpe)
    cpe = "cpe:/a:logitech:media_server";

  register_product(cpe:cpe, location:install, port:port, service:"www");

  log_message(data:build_detection_report(app:"Logitech Media Server",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:ver[0]),
                                          port:port);
}

exit(0);