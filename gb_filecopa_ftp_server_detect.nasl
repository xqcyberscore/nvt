###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_filecopa_ftp_server_detect.nasl 7297 2017-09-27 09:54:01Z cfischer $
#
# FileCopa FTP Server Version Detection
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

tag_summary = "This script detects the installed version of FileCopa FTP Server
  and sets the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801124");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 7297 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-27 11:54:01 +0200 (Wed, 27 Sep 2017) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FileCopa FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "summary" , value : "Detection of FileCopa FTP Server

This script detects the installed version of FileCopa FTP Server and sets the result in KB.");

  exit(0);
}


include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if("FileCOPA FTP Server" >< banner)
{
  version = "unknown";

  filecopeVer = eregmatch(pattern:"FileCOPA FTP Server Version ([0-9.]+)",
                          string:banner);
  if(!isnull(filecopeVer[1])) {
    version = filecopeVer[1];
    set_kb_item(name: "FileCOPA-FTP-Server/Ver", value: version);
  }

  set_kb_item(name: "FileCOPA-FTP-Server/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:filecopa-ftpserver:ftp_server:");
  if (!cpe)
    cpe = 'cpe:/a:filecopa-ftpserver:ftp_server';

  register_product(cpe: cpe, location: port + '/tcp', port: port);

  log_message(data: build_detection_report(app: "FileCOPA FTP Server", version: version, install: port,
                                           cpe: cpe, concluded: filecopeVer[0]),
              port: port);
  
  exit(0);
}

exit(0);
