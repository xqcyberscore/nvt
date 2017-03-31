###############################################################################
# OpenVAS Vulnerability Test
# $Id: cacti_27749.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Cacti Multiple Input Validation Vulnerabilities
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

tag_summary = "Cacti is prone to multiple unspecified input-validation
  vulnerabilities, including:

  - Multiple cross-site scripting vulnerabilities
  - Multiple SQL-injection vulnerabilities
  - An HTTP response-splitting vulnerability.

  Attackers may exploit these vulnerabilities to influence or
  misrepresent how web content is served, cached, or interpreted, to
  compromise the application, to access or modify data, to exploit
  vulnerabilities in the underlying database, or to execute arbitrary
  script code in the browser of an unsuspecting user.

  These issues affect Cacti 0.8.7a and prior versions.";

tag_solution = "Updates are available. Please see http://cacti.net/ for more
  information.";

if (description)
{
 script_id(100213);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-05-28 16:49:18 +0200 (Thu, 28 May 2009)");
 script_cve_id("CVE-2008-0786","CVE-2008-0785","CVE-2008-0784","CVE-2008-0783");
 script_bugtraq_id(27749);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Cacti Multiple Input Validation Vulnerabilities");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/27749");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/cacti")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "0.8.7b")) {
      security_message(port:port);
      exit(0);
  }  

} 

exit(0);
