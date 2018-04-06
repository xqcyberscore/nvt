###############################################################################
# OpenVAS Vulnerability Test
# $Id: simple_machines_forum_37182.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Simple Machines Forum Multiple Security Vulnerabilities
#
# Authors:
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

tag_summary = "Simple Machines Forum is prone to multiple security vulnerabilities:

- A remote PHP code-execution vulnerability
- Multiple cross-site scripting vulnerabilities
- Multiple cross-site request-forgery vulnerabilities
- An information-disclosure vulnerability
- Multiple denial-of-service vulnerabilities

 Attackers can exploit these issues to execute arbitrary script code
 within the context of the webserver, perform unauthorized actions on
 behalf of legitimate users, compromise the affected application,
 steal cookie-based authentication credentials, obtain information
 that could aid in further attacks or cause denial-of-service
 conditions.

Please note some of these issues may already be described in other
BIDs. This BID will be updated if further analysis confirms this.

These issues affect Simple Machines Forum 2.0 RC2. Some of these
issues also affect version 1.1.10.";

tag_solution = "Reportedly, the vendor fixed some of the issues in the release 1.1.11.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100371");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-12-02 17:30:58 +0100 (Wed, 02 Dec 2009)");
 script_bugtraq_id(37182);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_name("Simple Machines Forum Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37182");
 script_xref(name : "URL" , value : "http://www.simplemachines.org/");
 script_xref(name : "URL" , value : "http://code.google.com/p/smf2-review/issues/list");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_simple_machines_forum_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/SMF")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

 if(version_is_equal(version: vers, test_version: "1.1.10") ||
    version_is_equal(version: vers, test_version: "2.0.RC2")) {
        security_message(port:port);
        exit(0);
  }
}

exit(0);
