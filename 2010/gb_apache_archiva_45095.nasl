###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_archiva_45095.nasl 5263 2017-02-10 13:45:51Z teissa $
#
# Apache Archiva Cross Site Request Forgery Vulnerability
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

tag_summary = "Apache Archiva is prone to a cross-site request-forgery vulnerability.

Exploiting this issue may allow a remote attacker to perform certain
administrative actions and gain unauthorized access to the affected
application. Other attacks are also possible.

The following versions are affected:

Archiva versions 1.0 through 1.0.3
Archiva versions 1.1 through 1.1.4
Archiva versions 1.2 through 1.2.2
Archiva versions 1.3 through 1.3.1";

tag_solution = "Updates are available. Please see the reference for more details.";

if (description)
{
 script_id(100924);
 script_version("$Revision: 5263 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:45:51 +0100 (Fri, 10 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
 script_bugtraq_id(45095);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3449", "CVE-2010-4408");

 script_name("Apache Archiva Cross Site Request Forgery Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45095");
 script_xref(name : "URL" , value : "http://archiva.apache.org/download.html");
 script_xref(name : "URL" , value : "http://jira.codehaus.org/browse/MRM-1438");
 script_xref(name : "URL" , value : "http://archiva.apache.org/docs/1.3.2/release-notes.html");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_apache_archiva_detect.nasl");
 script_require_ports("Services/www", 8080);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"apache_archiva")) {

  if(version_in_range(version: vers, test_version: "1", test_version2:"1.0.3")   ||
     version_in_range(version: vers, test_version: "1.1", test_version2:"1.1.4") ||
     version_in_range(version: vers, test_version: "1.2", test_version2:"1.2.2") ||
     version_in_range(version: vers, test_version: "1.3", test_version2:"1.3.1")) {
       security_message(port:port);
       exit(0);
  }

}

exit(0);
