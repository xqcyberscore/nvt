###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sphere_ftp_server_detect.nasl 4777 2016-12-15 14:28:45Z cfi $
#
# SphereFTP Server Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.807533");
  script_version("$Revision: 4777 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-15 15:28:45 +0100 (Thu, 15 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-04-04 16:23:30 +0530 (Mon, 04 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("SphereFTP Server Remote Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  SphereFTP Server.

  The script sends a connection request to the server and attempts to
  extract the version from the reply");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  exit(0);
}

include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

ftpPort = get_ftp_port(default: 21);

# Get the FTP banner
banner = get_ftp_banner(port:ftpPort);

## Confirm the server from banner
if("Menasoft GrayFTP Server" >< banner)
{
  sphVer = eregmatch(pattern:"Menasoft GrayFTP Server \(v([0-9.]+)\)", string:banner);
  if(sphVer[1]){
    sphVer = sphVer[1];
    set_kb_item(name:"SphereFTP/Server/Ver", value:sphVer);
  } else {
    sphVer = "Unknown";
  }

  ##Set the KB
  set_kb_item(name:"SphereFTP Server/installed", value:TRUE);
  
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:sphVer, exp:"([0-9.]+)", base:"cpe:/a:menasoft:sphereftpserver:");
  if(isnull(cpe))
    cpe = "cpe:/a:menasoft:sphereftpserver";

  ##Register Product and Build Report
  register_product(cpe:cpe, location:"/", port:ftpPort);
  log_message(data: build_detection_report(app: "SphereFTP Server",
                                           version:sphVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:sphVer),
                                           port:ftpPort);
  exit(0);
}

exit(0);
