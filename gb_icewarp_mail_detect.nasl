###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_mail_detect.nasl 9845 2018-05-15 13:33:19Z cfischer $
#
# IceWarp Mail Server Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140330");
  script_version("$Revision: 9845 $");
  script_tag(name: "last_modification", value: "$Date: 2018-05-15 15:33:19 +0200 (Tue, 15 May 2018) $");
  script_tag(name: "creation_date", value: "2017-08-28 15:51:57 +0700 (Mon, 28 Aug 2017)");
  script_tag(name: "cvss_base", value: "0.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IceWarp Mail Server Detection");

  script_tag(name: "summary" , value: "Detection of IceWarp Mail Server.

The script sends a connection request to the server and attempts to detect IceWarp Mail Server and to
extract its version.");
  
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl", "find_service2.nasl");
  script_require_ports("Services/smtp", "Services/imap", "Services/pop3", 25, 465, 578, 143, 110);

  script_xref(name: "URL", value: "http://www.icewarp.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("smtp_func.inc");

function _report(port, version, concluded, service)
{
  if (!version || version == '')
    return;

  set_kb_item(name: "icewarp/installed", value: TRUE);
  set_kb_item(name: "icewarp/mail/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:icewarp:mail_server:");
  if (!cpe)
    cpe = 'cpe:/a:icewarp:mail_server';

  register_product(cpe: cpe, location: port + '/tcp', port: port, service: service);

  log_message(data: build_detection_report(app: "IceWarp", version: version, install: port + '/tcp', cpe: cpe,
                                           concluded: concluded),
              port: port);
  return;
}

# SMTP
ports = get_kb_list("Services/smtp");
if (!ports) ports = make_list(25, 465, 587);

foreach port (ports) {
  if (get_port_state(port)) {
    banner = get_smtp_banner(port: port);

    if ("ESMTP IceWarp" >< banner) {
      if (vers = eregmatch(pattern: "ESMTP IceWarp ([0-9.]+)", string: banner)) {
        _report(port: port, version: vers[1], concluded: banner, service: "smtp");
      }
    }
  }
}

# IMAP
ports = get_kb_list("Services/imap");
if (!ports) ports = make_list(143);

foreach port (ports) {
  if (get_port_state(port)) {
    banner = get_imap_banner(port: port);

    if ("IceWarp" >< banner) {
      if (vers = eregmatch(pattern: "IceWarp ([0-9.]+)", string: banner)) {
        _report(port: port, version: vers[1], concluded: banner, service: "imap");
      }
    }
  }
}

# POP3
ports = get_kb_list("Services/pop3");
if (!ports) ports = make_list(110);

foreach port (ports) {
  if (get_port_state(port)) {
    banner = get_pop3_banner(port: port);

    if ("IceWarp" >< banner) {
      if (vers = eregmatch(pattern: "IceWarp ([0-9.]+)", string: banner)) {
        _report(port: port, version: vers[1], concluded: banner, service: "pop3");
      }
    }
  }
}

exit(0);
