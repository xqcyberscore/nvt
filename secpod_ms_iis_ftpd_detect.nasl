##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_ftpd_detect.nasl 4777 2016-12-15 14:28:45Z cfi $
#
# Microsoft IIS FTP Server Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900875");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 4777 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-15 15:28:45 +0100 (Thu, 15 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Microsoft IIS FTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name: "summary" , value: "Detection of Microsoft IIS FTP Server

The script sends a connection request to the server and attempts to extract the version number from the reply.");
  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");
include("version_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if("Microsoft FTP Service" >< banner)
{
  version = "unknown";

  set_kb_item(name:"MS/IIS-FTP/Installed", value:TRUE);
  ver = eregmatch(pattern:"Microsoft FTP Service \(Version ([0-9.]+)\)",
                  string:banner);
  if(!isnull(ver[1]))
  {
    version = ver[1];
    set_kb_item(name: "MS/IIS-FTP/Ver", value: version);
  }

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:iis_ftp:");
  if(isnull(cpe))
    cpe = 'cpe:/a:microsoft:iis_ftp';

  register_product(cpe: cpe, location: port + '/tcp', port:port);

  log_message(data: build_detection_report(app: "Microsoft IIS FTP Server ", version: version,
                                           install: port + '/tcp', cpe: cpe, concluded: ver[0]),
              port:port);
  exit(0);
}

exit(0);
