###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xm_easy_personal_ftp_detect.nasl 9536 2018-04-19 11:20:50Z cfischer $
#
# XM Easy Personal FTP Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801119");
  script_version("$Revision: 9536 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-19 13:20:50 +0200 (Thu, 19 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("XM Easy Personal FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp_banner/available");

  script_tag(name: "summary", value: "Detection of XM Easy Personal FTP Server.

  This script detects the installed version of XM Easy Personal FTP Server and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port: port);

if("220 Welcome to DXM's FTP Server" >< banner) {

  version = "unknown";

  xmVer = eregmatch(pattern: "DXM's FTP Server ([0-9.]+)", string: banner);
  if (!isnull(xmVer[1])) {
    version = xmVer[1];
    set_kb_item(name: "XM-Easy-Personal-FTP/Ver", value: version);
  }

  set_kb_item(name: "XM-Easy-Personal-FTP/installed", value: TRUE);

  cpe = build_cpe(value: xmVer[1], exp: "^([0-9.]+)", base: "cpe:/a:dxmsoft:xm_easy_personal_ftp_server:");
  if (!cpe)
    cpe = 'cpe:/a:dxmsoft:xm_easy_personal_ftp_server';

  register_product(cpe: cpe, location: port + '/tcp', port: port);

  log_message(data: build_detection_report(app: "XM Easy Personl FTP Server", version: version,
                                           install: port + '/tcp', cpe: cpe, concluded: banner),
              port: port);
}

exit(0);
