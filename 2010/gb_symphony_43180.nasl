###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_43180.nasl 6705 2017-07-12 14:25:59Z cfischer $
#
# Symphony SQL Injection and HTML Injection Vulnerabilities
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

tag_summary = "Symphony is prone to an SQL-injection vulnerability and an HTML-
injection vulnerability because it fails to sufficiently sanitize user-
supplied input.

An attacker may leverage these issues to compromise the application,
access or modify data, exploit latent vulnerabilities in the
underlying database, or execute arbitrary script code in the browser
of an unsuspecting user in the context of the affected site. This may
allow the attacker to steal cookie-based authentication credentials,
control how the site is viewed, and launch other attacks.

Symphony 2.1.1 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100799";
CPE = "cpe:/a:symphony-cms:symphony_cms";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 6705 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:25:59 +0200 (Wed, 12 Jul 2017) $");
 script_tag(name:"creation_date", value:"2010-09-14 15:16:41 +0200 (Tue, 14 Sep 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-3457", "CVE-2010-3458");
 script_bugtraq_id(43180);

 script_name("Symphony SQL Injection and HTML Injection Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43180");
 script_xref(name : "URL" , value : "http://symphony-cms.com/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_symphony_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("symphony/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_equal(version: vers, test_version: "2.1.1")) {
      security_message(port:port);
      exit(0);
  }
}

exit(0);
