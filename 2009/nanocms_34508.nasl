###############################################################################
# OpenVAS Vulnerability Test
# $Id: nanocms_34508.nasl 13235 2019-01-23 10:05:41Z ckuersteiner $
#
# NanoCMS '/data/pagesdata.txt' Password Hash Information Disclosure
# Vulnerability
#
# Authors
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

CPE = "cpe:/a:nanocms:nanocms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100141");
  script_version("$Revision: 13235 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 11:05:41 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_bugtraq_id(34508);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("NanoCMS '/data/pagesdata.txt' Password Hash Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("nanocms_detect.nasl");
  script_mandatory_keys("nanocms/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NanoCMS is prone to an information-disclosure vulnerability because
  it fails to validate access to sensitive files.

  An attacker can exploit this vulnerability to obtain sensitive
  information that may lead to further attacks.

  NanoCMS 0.4_final is vulnerable, other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34508");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/data/pagesdata.txt";

if (http_vuln_check(port: port, url: url, pattern: "password.*[a-f0-9]{32}", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
