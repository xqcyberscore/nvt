###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_51048.nasl 3116 2016-04-19 10:11:19Z benallard $
#
# Cacti Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Cacti is prone to multiple multiple input-validation vulnerabilities
including:

1. Multiple cross-site scripting vulnerabilities.
2. A cross-site request-forgery vulnerability.
3. An HTML-injection vulnerability.

An attacker can exploit these vulnerabilities to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials,
disclose or modify sensitive information, or perform unauthorized
actions. Other attacks are also possible.

Versions prior to Cacti 0.8.7i are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103365);
 script_bugtraq_id(51048);
 script_version ("$Revision: 3116 $");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Cacti Multiple Input Validation Vulnerabilities");


 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:11:19 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-12-14 11:24:31 +0100 (Wed, 14 Dec 2011)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed Cacti version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51048");
 script_xref(name : "URL" , value : "http://cacti.net/");
 script_xref(name : "URL" , value : "http://forums.cacti.net/viewtopic.php?f=4&t=45871");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"cacti")) {

  if(version_is_less_equal(version: vers, test_version: "0.8.7i")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
