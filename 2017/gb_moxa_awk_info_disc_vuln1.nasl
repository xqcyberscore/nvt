###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_awk_info_disc_vuln1.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Moxa AWK Series Systemlog Information Disclosure Vulnerability
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

CPE = "cpe:/h:moxa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106741");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-11 14:59:45 +0200 (Tue, 11 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-8725");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa AWK Series Systemlog Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_awk_detect.nasl");
  script_mandatory_keys("moxa_awk/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Moxa AWK series wireless access points are prone to a systemlog.log
information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a HTTP request and checks the response.");

  script_tag(name:"insight", value:"The file systemlog.log can be accessed without any authentication which
might reveal sensitive information.");

  script_tag(name:"impact", value:"An unauthenticated attacker may obtain sentive information.");

  script_tag(name:"solution", value:"Update to version 1.4 or later.");

  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0239/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port_from_cpe_prefix(cpe: CPE))
  exit(0);

url = "/systemlog.log";

if (http_vuln_check(port: port, url: url, pattern: "\([0-9]+\) [0-9/]+,[0-9]+h:[0-9]+m:[0-9]+s",
                    check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
