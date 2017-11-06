###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_code_rce_vuln.nasl 7651 2017-11-03 13:41:18Z cfischer $
#
# Zabbix Server Active Proxy Trapper Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106835");
  script_version("$Revision: 7651 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-03 14:41:18 +0100 (Fri, 03 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-05-29 11:13:22 +0700 (Mon, 29 May 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-2824");

  script_tag(name: "qod_type", value: "remote_banner_unreliable");

  script_tag(name: "solution_type", value: "Mitigation");

  script_name("Zabbix Server Active Proxy Trapper Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("zabbix_web_detect.nasl");
  script_mandatory_keys("Zabbix/installed");

  script_tag(name: "summary", value: "An exploitable code execution vulnerability exists in the trapper command
functionality of Zabbix Server. A specially crafted set of packets can cause a command injection resulting in
remote code execution. An attacker can make requests from an active Zabbix Proxy to trigger this vulnerability.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "affected", value: "Zabbix version 2.4.x");

  script_tag(name: "solution", value: "By removing the three default script entries inside of the Zabbix Server's
'Zabbix' database, an attacker would be unable to actually execute code, even if they can insert hosts with
spoofed addresses into the database. This should not affect an organizations current operations, unless the
scripts are actually used.");

  script_xref(name: "URL", value: "https://talosintelligence.com/vulnerability_reports/TALOS-2017-0325");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.4") {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
