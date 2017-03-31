###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_44618.nasl 5263 2017-02-10 13:45:51Z teissa $
#
# Bugzilla Response Splitting and Security Bypass Vulnerabilities
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

tag_summary = "Bugzilla is prone to a response-splitting vulnerability and a security-
bypass vulnerability.

Successfully exploiting these issues may allow an attacker to bypass
certain security restrictions; obtain sensitive information; and
influence or misrepresent how web content is served, cached, or
interpreted. This could aid in various attacks that try to instill
client users with a false sense of trust.

These issues affect versions prior to 3.2.9, 3.4.9, and 3.6.3.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100892);
 script_version("$Revision: 5263 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:45:51 +0100 (Fri, 10 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)");
 script_bugtraq_id(44618);
 script_cve_id("CVE-2010-3172","CVE-2010-3764");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Bugzilla Response Splitting and Security Bypass Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44618");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.2.8/");
 script_xref(name : "URL" , value : "http://www.bugzilla.org");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("bugzilla_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"bugzilla/version")) {

  if(version_in_range(version:vers, test_version: "3.6", test_version2:"3.6.2") ||
     version_in_range(version:vers, test_version: "3.4", test_version2:"3.4.8") ||
     version_in_range(version:vers, test_version: "3.2", test_version2:"3.2.8")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
