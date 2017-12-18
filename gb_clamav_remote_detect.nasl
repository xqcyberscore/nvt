###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_remote_detect.nasl 8137 2017-12-15 11:26:42Z cfischer $
#
# ClamAV Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100651");
  script_version("$Revision: 8137 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:26:42 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-06-17 14:03:59 +0530 (Wed, 17 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ClamAV Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  ClamAV Anti Virus.

  This script sends a connection request to the server and try
  to get the version from the response, and sets the result in KB.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/clamd", 3310);
  exit(0);
}


include("global_settings.inc");
include("host_details.inc");
include("cpe.inc");

## Get ClamAV Port
clamPort = get_kb_item("Services/clamd");
if(!clamPort) clamPort = 3310;
if(!get_port_state(clamPort))exit(0);

soc = open_sock_tcp(clamPort);
if(!soc)exit(0);

req = string("VERSION\r\n");
send(socket:soc, data:req);

buf = recv(socket:soc, length:256);

if(buf == NULL || "clamav" >!< tolower(buf))exit(0);
version = eregmatch(pattern:"clamav ([0-9.]+)", string:tolower(buf));

if(!version){
  version = "Unknown";
} else{
  version = version[1];
}

## Set the KB
set_kb_item(name:"ClamAV/installed", value:TRUE);
set_kb_item(name:"ClamAV/remote/Ver", value: version);

## build cpe and store it as host_detail
cpe = build_cpe(value: version, exp:"([0-9.]+)", base:"cpe:/a:clamav:clamav:");
if(isnull(cpe))
  cpe = "cpe:/a:clamav:clamav";

## Register Product and Build Report
register_product(cpe:cpe, location:clamPort, port:clamPort);
log_message(data: build_detection_report(app: "ClamAV",
                                         version:version,
                                         install:clamPort,
                                         cpe:cpe,
                                         concluded:version),
                                         port:clamPort);

info = string("ClamAV Version (" + version + ") was detected on the remote host.\n");
if(report_verbosity > 0) 
{
  security_message(port:clamPort,data:info);
  exit(0);
}
