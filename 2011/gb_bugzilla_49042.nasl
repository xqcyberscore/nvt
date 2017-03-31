###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_49042.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Bugzilla Multiple Security Vulnerabilities
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

tag_summary = "Bugzilla is prone to the following vulnerabilities:

1. A security-bypass vulnerability.
2. An email header-injection vulnerability.
3. Multiple information-disclosure vulnerabilities.
4. Multiple cross-site scripting vulnerabilities.

Successfully exploiting these issues may allow an attacker to bypass
certain security restrictions, obtain sensitive information, execute
arbitrary script code in the browser of an unsuspecting user, steal
cookie-based authentication credentials, and perform actions in the
vulnerable application in the context of the victim.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(103215);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-08-22 16:04:33 +0200 (Mon, 22 Aug 2011)");
 script_bugtraq_id(49042);
 script_cve_id("CVE-2011-2379","CVE-2011-2380","CVE-2011-2381","CVE-2011-2976","CVE-2011-2977","CVE-2011-2978","CVE-2011-2979");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("Bugzilla Multiple Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49042");
 script_xref(name : "URL" , value : "http://www.bugzilla.org");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.4.11/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed Bugzilla version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("bugzilla_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"bugzilla/version")) {

  if(version_in_range(version: vers, test_version:"4.1", test_version2:"4.1.2") ||
     version_in_range(version: vers, test_version:"4.0", test_version2:"4.0.1") ||
     version_in_range(version: vers, test_version:"3.6", test_version2:"3.6.5") ||
     version_in_range(version: vers, test_version:"3.4", test_version2:"3.4.11")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
