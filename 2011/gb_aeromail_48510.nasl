###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aeromail_48510.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# AeroMail Cross Site Request Forgery, HTML Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "AeroMail is prone to multiple remote vulnerabilities, including:

1. A cross-site scripting vulnerability.

2. Multiple HTML-injection vulnerabilities.

3. Multiple cross-site request forgery vulnerabilities.

The attacker can exploit the cross-site scripting issue to execute
arbitrary script code in the context of the vulnerable site,
potentially allowing the attacker to steal cookie-based authentication
credentials. The attacker may also be perform certain administrative
functions and delete arbitrary files. Other attacks are also possible.";

tag_solution = "A third party patch is available. Please see the references for
details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103205");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");
 script_bugtraq_id(48510);

 script_name("AeroMail Cross Site Request Forgery, HTML Injection and Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48510");
 script_xref(name : "URL" , value : "http://www.nicolaas.net/aeromail/index.php?page=index");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_aeromail_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"AeroMail")) {

  if(version_is_equal(version: vers, test_version: "2.80")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
