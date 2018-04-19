###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpdmin_detect.nasl 9537 2018-04-19 11:49:54Z cfischer $
#
# Ftpdmin Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100131");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 9537 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-19 13:49:54 +0200 (Thu, 19 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Ftpdmin Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp_banner/available");

  script_xref(name:"URL", value:"http://www.sentex.net/~mwandel/ftpdmin/");

  script_tag(name:"summary", value:"Detection of Ftpdmin.

  Ftpdmin is running at this port. Ftpdmin is a minimal Windows FTP server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_ftp_port(default:21);
if(!banner = get_ftp_banner(port:port))exit(0);

if("Minftpd" >< banner) {

  vers = "unknown";

  soc = open_sock_tcp(port);
  if (! soc) exit(0);
  ftp_recv_line(socket:soc);

  syst = string("syst\r\n");
  send(socket:soc, data:syst);
  line = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  version = eregmatch(pattern:"^215.*ftpdmin v\. ([0-9.]+)", string:line);
  if(!isnull(version[1])) vers = version[1];

  set_kb_item(name:"ftpdmin/Ver", value:vers);
  set_kb_item(name:"ftpdmin/installed", value:TRUE);

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:ftpdmin:ftpdmin:");
  if (!cpe)
    cpe = 'cpe:/a:ftpdmin:ftpdmin';

  register_product(cpe:cpe, location:port + '/tcp', port:port);

  log_message(data:build_detection_report(app:"Ftpdmin", version:vers, install:port + '/tcp',
                                          cpe:cpe, concluded:version[0]),
              port:port);
}

exit(0);
