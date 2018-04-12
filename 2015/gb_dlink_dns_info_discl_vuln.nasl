###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dns_info_discl_vuln.nasl 9442 2018-04-11 12:22:50Z cfischer $
#
# D-Link DNS Devices Multiple Information Disclosure Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.106016");
  script_version("$Revision: 9442 $");
  script_tag(name : "last_modification", value : "$Date: 2018-04-11 14:22:50 +0200 (Wed, 11 Apr 2018) $");
  script_tag(name : "creation_date", value : "2015-07-10 14:32:27 +0700 (Fri, 10 Jul 2015)");
  script_tag(name : "cvss_base", value : "5.0");
  script_tag(name : "cvss_base_vector", value : "AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name: "qod_type", value:"remote_vul");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("D-Link DNS Devices Multiple Information Disclosure Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dns_detect.nasl");
  script_mandatory_keys("host_is_dlink_dns");

  script_tag(name : "summary", value : "Multiple information disclosure vulnerabilities in D-Link DNS
series devices.");

  script_tag(name : "vuldetect", value : "Send a special crafted HTTP GET request and check the response.");

  script_tag(name : "insight", value : "D-Link DNS series devices allow unauthenticated attackers to gain
system information. The CGI scripts info.cgi, discovery.cgi, status_mgr.cgi, widget_api.cgi, wizard_mgr.cgi
and app_mgr.cgi give detailed information about the settings and versions of the system back.");

  script_tag(name : "impact", value : "An unauthenticated attacker can gain information about the system and
its configuration which will help to customize further attacks.");

  script_tag(name : "affected", value : "DNS-320, DNS-320L, DNS-325, DNS-327L");

  script_tag(name : "solution", value : "Update the Firmware to the latest available version");

  script_xref(name : "URL", value : "http://www.search-lab.hu/media/D-Link_Security_advisory_3_0_public.pdf");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_kb_item("dlink_dns_port"))
  exit(0);

# Checking 3 issues should be enough

# info.cgi
if (http_vuln_check(port: port, url: "/cgi-bin/info.cgi", pattern: "Product=",
                    extra_check: "Model=", check_header: TRUE)) {
  security_message(port: port);
  exit(0);
}

# discovery.cgi
if (http_vuln_check(port: port, url: "/cgi-bin/discovery.cgi", pattern: "<entry>",
                    extra_check: "<ConnectType>", check_header: TRUE)) {
  security_message(port: port);
  exit(0);
}

# status_mgr.cgi
if (http_vuln_check(port: port, url: "/cgi-bin/status_mgr.cgi?cmd=cgi_get_status",
                    pattern: "<status>", extra_check: "<uptime>", check_header: TRUE)) {
  security_message(port: port);
  exit(0);
}

exit(99);
