###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xitami_server_detect.nasl 9541 2018-04-19 13:42:33Z cfischer $
#
# Xitami Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900547");
  script_version("$Revision: 9541 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-19 15:42:33 +0200 (Thu, 19 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Xitami Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/www", 80, "Services/ftp", 21);

  script_tag(name:"summary", value:"Detection of Xitami Server.

  This script detects the installed version of Xitami Server and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ftp_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

wwwPort = get_http_port(default:80);

rcvRes = http_get_cache(port: wwwPort, item: "/");

if("Xitami" >< rcvRes){
  version = "unknown";
  port = wwwPort;
  location = "/";

  xitaVer = eregmatch(pattern:"Xitami(\/([0-9]\.[0-9.]+)([a-z][0-9]?)?)",
                      string:rcvRes);
  if(isnull(xitaVer[1]))
  {
    req = http_get(port: wwwPort, item: "/xitami/index.htm");
    res = http_keepalive_send_recv(port: wwwPort, data: req);
    xitaVer = eregmatch(pattern: "Xitami</B>.*Version ([0-9]\.[0-9a-z.]+)", string: res);

    if (isnull(xitaVer[1])) {
      ftpPort = get_ftp_port(default: 21);

      # Get the version from banner
      banner = get_ftp_banner(port:ftpPort);
      xitaVer = eregmatch(pattern: "Xitami FTP ([0-9a-z.]+)", string: banner);
      if (!isnull(xitaVer[1])) {
        port = ftpPort;
        location = port + '/tcp';
      }
    }
  }

  if (!isnull(xitaVer[1])) {
    xVer = xitaVer[1];
    set_kb_item(name: "Xitami/Ver", value: xVer);
  }

  set_kb_item(name: "Xitami/installed", value: TRUE);

  cpe = build_cpe(value: xVer, exp: "^([0-9a-z.]+)", base: "cpe:/a:imatix:xitami:");
  if (!cpe)
    cpe = 'cpe:/a:imatix:xitami';

  register_product(cpe: cpe, location: location, port: port);

  log_message(data: build_detection_report(app: "Xitami Server", version: xVer, install: location, cpe: cpe,
                                           concluded: xitaVer[0]),
              port: port);
  exit(0);
}

exit(0);
