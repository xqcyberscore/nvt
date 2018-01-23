###############################################################################
# OpenVAS Vulnerability Test
# $Id: barracuda_web_application_firewall_37432.nasl 8487 2018-01-22 10:21:31Z ckuersteiner $
#
# Barracuda Web Application Firewall 660 'cgi-mod/index.cgi' Multiple HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:barracuda:web_application_firewall";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100420");
 script_version("$Revision: 8487 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-22 11:21:31 +0100 (Mon, 22 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
 script_bugtraq_id(37432);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Barracuda Web Application Firewall 660 'cgi-mod/index.cgi' Multiple HTML Injection Vulnerabilities");

 script_xref(name: "URL", value: "http://www.securityfocus.com/bid/37432");
 script_xref(name: "URL", value: "http://www.barracudanetworks.com/ns/products/web-site-firewall-overview.php");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("barracuda_web_application_firewall_detect.nasl");
 script_mandatory_keys("barracuda_waf/installed");

 script_tag(name: "summary", value: "The Barracuda Web Application Firewall 660 is prone to multiple HTML-
injection vulnerabilities.

Attacker-supplied HTML and script code would execute in the context of the affected site, potentially allowing the
attacker to steal cookie-based authentication credentials or to control how the site is rendered to the user;
other attacks are also possible.

The Barracuda Web Application Firewall 660 firmware 7.3.1.007 is vulnerable; other versions may also be
affected.");

 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_equal(version: version, test_version: "7.3.1.007")) {
  security_message(port:port);
  exit(0);
}

exit(0);
