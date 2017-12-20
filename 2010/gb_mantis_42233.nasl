###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_42233.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# Mantis 'manage_proj_cat_add.php' HTML Injection Vulnerability
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

tag_summary = "Mantis is prone to an HTML-injection vulnerability because it fails to
properly sanitize user-supplied input before using it in dynamically
generated content.

Successful exploits will allow attacker-supplied HTML and script
code to run in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials or to control how the site is rendered to the user.
Other attacks are also possible.

Mantis 1.2.2 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100746");
 script_version("$Revision: 8168 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-08-06 12:49:38 +0200 (Fri, 06 Aug 2010)");
 script_bugtraq_id(42233);
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2574");

 script_name("Mantis 'manage_proj_cat_add.php' HTML Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42233");
 script_xref(name : "URL" , value : "http://www.mantisbt.org/");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-103/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mantis_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"mantis")) {
  if(version_is_equal(version: vers, test_version: "1.2.2")) {
      security_message(port:port);
      exit(0);
  }
}

exit(0);

