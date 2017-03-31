###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_42575.nasl 5263 2017-02-10 13:45:51Z teissa $
#
# Cacti Cross Site Scripting and HTML Injection Vulnerabilities
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

tag_summary = "Cacti is prone to cross-site-scripting and HTML-injection
vulnerabilities because it fails to properly sanitize user-supplied
input before using it in dynamically generated content.

Attacker-supplied HTML and script code would run in the context of the
affected browser, potentially allowing the attacker to steal cookie-
based authentication credentials or to control how the site is
rendered to the user. Other attacks are also possible.

Versions prior to Cacti 0.8.7g are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100764);
 script_version("$Revision: 5263 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:45:51 +0100 (Fri, 10 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-30 14:30:07 +0200 (Mon, 30 Aug 2010)");
 script_bugtraq_id(42575);
 script_cve_id("CVE-2010-2544","CVE-2010-2545");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Cacti Cross Site Scripting and HTML Injection Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42575");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=459105");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=459229");
 script_xref(name : "URL" , value : "http://cacti.net/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"cacti")) {

  if(version_is_less(version: vers, test_version: "0.8.7g")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);

