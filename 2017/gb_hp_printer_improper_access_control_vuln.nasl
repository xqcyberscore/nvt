# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807397");
  script_version("2019-10-07T14:48:59+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-10-07 14:48:59 +0000 (Mon, 07 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-02-14 12:24:12 +0530 (Tue, 14 Feb 2017)");
  script_name("HP Printer Wi-Fi Direct Improper Access Control Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/port", "hp_model");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://neseso.com/advisories/NESESO-2017-0111.pdf");
  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2017020027");
  script_xref(name:"URL", value:"http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04577030");
  script_xref(name:"URL", value:"http://h20564.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04090221");
  script_xref(name:"URL", value:"http://007software.net/hp-printers-wi-fi-direct-improper-access-control");

  script_tag(name:"summary", value:"This HP printer is prone to an improper access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks whether the device is vulnerable or not by trying
  to access restricted pages.");

  script_tag(name:"insight", value:"HP printers with Wi-Fi Direct support
  let you print from a mobile device directly to the printer without connecting
  to a wireless network. Several of these printers are prone to a security
  vulnerability that allows an external system to obtain unrestricted remote
  read/write access to the printer configuration using the embedded web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated user to access certain files on the target system that are
  not intended to be accessible.");

  script_tag(name:"affected", value:"HP OfficeJet Pro 8710 firmware version WBP2CN1619BR

  HP OfficeJet Pro 8620 firmware version FDP1CN1547AR");

  script_tag(name:"solution", value:"Apply the following mitigation actions:

  - Disable Wi-Fi Direct functionality to protect your device

  - Enable Password Settings on the Embedded Web Server");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("hp_printer/port");
if(!port)
  exit(0);

model = get_kb_item("hp_model");
if(!model)
  exit(0);

if("Officejet Pro 8620" >< model || "Officejet Pro 8710" >< model) {
  vuln_url = "/DevMgmt/Email/Contacts";

  if(http_vuln_check(port:port, url:vuln_url, check_header:TRUE, pattern:"<emaildyn:EmailContacts xmlns:dd=",
     extra_check:make_list("www\.hp\.com", "xmlns:emaildyn=", "emailservicedyn", "dictionaries"))) {
    report = report_vuln_url(port:port, url:vuln_url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
