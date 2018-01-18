###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mahara_41319.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Mahara Multiple Remote Vulnerabilities
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

tag_summary = "Mahara is prone to multiple remote vulnerabilities, including:

1. Multiple HTML-injection vulnerabilities
2. A cross-site request-forgery vulnerability
3. Multiple SQL-injection vulnerabilities
4. An authentication-bypass vulnerability

Exploiting these issues could allow an attacker to steal cookie-based
authentication credentials, control how the site is rendered to the
user, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database, gain unauthorized
access to the application and perform certain administrative tasks.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100697");
 script_version("$Revision: 8447 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)");
 script_bugtraq_id(41319);
 script_cve_id("CVE-2010-1667","CVE-2010-1668","CVE-2010-1669","CVE-2010-1670");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Mahara Multiple Remote Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41319");
 script_xref(name : "URL" , value : "http://wiki.mahara.org/Release_Notes/1.0.15");
 script_xref(name : "URL" , value : "http://wiki.mahara.org/Release_Notes/1.1.9");
 script_xref(name : "URL" , value : "http://wiki.mahara.org/Release_Notes/1.2.5");
 script_xref(name : "URL" , value : "http://mahara.org/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_mahara_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"Mahara")) {

  if(version_in_range(version: vers, test_version: "1.0", test_version2: "1.0.14") ||
     version_in_range(version: vers, test_version: "1.1", test_version2: "1.1.8") ||
     version_in_range(version: vers, test_version: "1.2", test_version2: "1.2.4")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
