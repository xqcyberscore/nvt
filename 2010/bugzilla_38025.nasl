###############################################################################
# OpenVAS Vulnerability Test
# $Id: bugzilla_38025.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# Bugzilla Directory Access Information Disclosure Vulnerability
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

tag_summary = "Bugzilla is prone to an information-disclosure vulnerability.

Exploits may allow attackers to obtain potentially sensitive
information that may aid in other attacks.

Versions prior to Bugzilla 3.0.11, 3.2.6, 3.4.5, and 3.5.3 are
affected.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100482");
 script_version("$Revision: 8356 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-02-02 21:07:02 +0100 (Tue, 02 Feb 2010)");
 script_bugtraq_id(38025);
 script_cve_id("CVE-2009-3989");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_name("Bugzilla Directory Access Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38025");
 script_xref(name : "URL" , value : "http://www.bugzilla.org");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.0.10/");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
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

if(!version = get_kb_item(string("www/", port, "/bugzilla")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "3.0.11") ||
     version_in_range(version: vers, test_version: "3.1", test_version2: "3.2.5") ||
     version_in_range(version: vers, test_version: "3.3", test_version2: "3.4.4") ||
     version_in_range(version: vers, test_version: "3.5", test_version2: "3.5.2")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
