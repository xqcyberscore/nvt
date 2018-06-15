###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitvise_ssh_server_detect.nasl 10182 2018-06-14 07:00:55Z santu $
#
# Bitvise SSH Server Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813383");
  script_version("$Revision: 10182 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-14 09:00:55 +0200 (Thu, 14 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-04 12:52:08 +0530 (Mon, 04 Jun 2018)");
  script_name("Bitvise SSH Server Detection");

  script_tag(name:"summary", value:"Detection of running version of
  Bitvise SSH Server.

  This script sends connection request and try to ensure the presence of
  Bitvise SSH Server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

sshport = get_kb_item("Services/ssh");
if (!sshport || !get_port_state(sshport))
  exit(0);

server_banner = get_ssh_server_banner( port:sshport );

if(server_banner =~ "SSH.*Bitvise SSH Server \(WinSSHD\)")
{
  btVer = "Unknown";
  set_kb_item(name:"BitviseSSH/Server/Installed", value:TRUE);

  btVer = eregmatch(pattern:"Bitvise SSH Server \(WinSSHD\) ([0-9.]+)", string:server_banner);
  if(btVer[1])
  {
    set_kb_item(name:"BitviseSSH/Server/Version", value:btVer[1]);
    btVer = btVer[1] ;
  }
  
  cpe = build_cpe(value:btVer, exp: "^([0-9.]+)", base:"cpe:/a:bitvise:winsshd:");
  if (!cpe)
    cpe = 'cpe:/a:bitvise:winsshd';

  register_product(cpe:cpe, location:sshport + "/tcp", port:sshport, service: "ssh");

  log_message(data: build_detection_report(app: "Bitvise SSH Server",
                                           version: btVer,
                                           install: sshport + "/tcp",
                                           cpe: cpe,
                                           concluded: "Bitvise SSH Server " + btVer),
                                           port: sshport);
}
exit(0);
