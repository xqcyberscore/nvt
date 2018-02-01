###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jira_dir_trav_vuln.nasl 8596 2018-01-31 08:17:43Z cfischer $
#
# Atlassian JIRA Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:atlassian:jira';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106154");
  script_version("$Revision: 8596 $");
  script_tag(name: "last_modification", value: "$Date: 2018-01-31 09:17:43 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name: "creation_date", value: "2016-07-27 15:23:00 +0700 (Wed, 27 Jul 2016)");
  script_tag(name: "cvss_base", value: "4.3");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name: "qod_type", value: "remote_banner");

  script_cve_id("CVE-2014-2313", "CVE-2014-2314");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Atlassian JIRA Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_atlassian_jira_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("atlassian_jira/installed","Host/runs_windows");

  script_tag(name: "summary", value: "Atlassian JIRA is prone to two directory traversal vulnerabilities.");


  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "Atlassian JIRA is prone to two directory traversal vulnerabilities:

Directory traversal vulnerability in the Importers plugin allows remote attackers to create arbitrary files
via unspecified vectors. (CVE-2014-2313)

Directory traversal vulnerability in the Issue Collector plugin allows remote attackers to create arbitrary
files via unspecified vectors. (CVE-2014-2314)");

  script_tag(name: "impact", value: "An unauthenticated remote attacker may upload arbitrary files.");

  script_tag(name: "affected", value: "Versions prior to 6.0.5 on Windows");

  script_tag(name: "solution", value: "Upgrade to 6.0.5");

  script_xref(name: "URL", value: "http://blog.h3xstream.com/2014/02/jira-path-traversal-explained.html");
  script_xref(name: "URL", value: "https://confluence.atlassian.com/jira/jira-security-advisory-2014-02-26-445188412.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "6.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
