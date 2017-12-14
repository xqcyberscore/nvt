###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_45123.nasl 8083 2017-12-12 06:49:29Z ckuersteiner $
#
# Awstats Configuration File Remote Arbitrary Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:awstats:awstats";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100925");
 script_version("$Revision: 8083 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-12 07:49:29 +0100 (Tue, 12 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
 script_cve_id("CVE-2010-4367", "CVE-2010-4368");
 script_bugtraq_id(45123);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Awstats Configuration File Remote Arbitrary Command Execution Vulnerability");

 script_xref(name: "URL", value: "https://www.securityfocus.com/bid/45123");
 script_xref(name: "URL", value: "http://www.kb.cert.org/vuls/id/870532");
 script_xref(name: "URL", value: "http://www.exploitdevelopment.com/Vulnerabilities/2010-WEB-001.html");
 script_xref(name: "URL", value: "http://awstats.sourceforge.net/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("awstats_detect.nasl", "os_detection.nasl");
 script_mandatory_keys("awstats/installed", "Host/runs_windows");

 script_tag(name: "summary", value: "Awstats is prone to an arbitrary command-execution vulnerability. This issue
is due to a failure in the application to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to execute arbitrary shell commands in the context of the webserver
process. This may help attackers compromise the underlying system; other attacks are also possible.

Awstats < 7.0 is vulnerable;");

 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version: "6.95")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
