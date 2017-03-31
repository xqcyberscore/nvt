###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_solarwinds_fsm_detect.nasl 2664 2016-02-16 07:43:49Z antu123 $
#
# Solarwinds Firewall Security Manager Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.106013");
 script_version ("$Revision: 2664 $");
 script_tag(name: "last_modification", value: "$Date: 2016-02-16 08:43:49 +0100 (Tue, 16 Feb 2016) $");
 script_tag(name: "creation_date", value: "2015-06-30 10:54:34 +0700 (Tue, 30 Jun 2015)");
 script_tag(name: "cvss_base", value: "0.0");
 script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

 script_tag(name: "qod_type", value: "remote_active");

 script_name("Solarwinds Firewall Security Manager Detection");

 script_tag(name: "summary" , value: "Detection of Solarwinds Firewall Security Manager

The script sends a connection request to the server and attempts to detect Solarwinds Firewall
Security Manager (FSM).");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_family("Product detection");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 48080);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_summary("Checks for the presence of Solarwinds Firewall Security Manager.");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 48080);

foreach dir (make_list("/fsm", cgi_dirs())) {
  rep_dir = dir;
  if (dir == "/")
    dir = "";

  url = dir + '/login.jsp';
  req = http_get(item: url, port: port);
  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  if (buf =~ "HTTP/1\.. 200" && buf =~ "SolarWinds FSM Change Advisor") {
    vers = string("unknown");
    set_kb_item(name: "solarwinds_fsm/installed", value: TRUE);

    cpe = 'cpe:/a:solarwinds:firewall_security_manager';

    register_product(cpe: cpe, location: rep_dir, port: port);

    log_message(data: build_detection_report(app:"Solarwinds Firewall Security Manager", 
                                             version: vers, install: rep_dir, cpe: cpe),
                port: port);
  }
}

exit(0);
