###############################################################################
# OpenVAS Vulnerability Test
# $Id: cacti_37109.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Cacti Multiple HTML Injection Vulnerabilities
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

tag_summary = "Cacti is prone to multiple HTML-injection vulnerabilities because it
fails to properly sanitize user-supplied input before using it in
dynamically generated content.

Attacker-supplied HTML and script code would run in the context of the
affected browser, potentially allowing the attacker to steal cookie-
based authentication credentials or to control how the site is
rendered to the user. Other attacks are also possible.

Cacti 0.8.7e is vulnerable; other versions may be affected as well.";


tag_solution = "A patch is available. Please see the references for details.";

if (description)
{
 script_id(100361);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-11-25 11:49:08 +0100 (Wed, 25 Nov 2009)");
 script_cve_id("CVE-2009-4032");
 script_bugtraq_id(37109);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Cacti Multiple HTML Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37109");
 script_xref(name : "URL" , value : "http://cacti.net/");
 script_xref(name : "URL" , value : "http://docs.cacti.net/#cross-site_scripting_fixes");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/cacti")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "0.8.7e")) {
     security_message(port:port);
     exit(0);
   }  

} 

exit(0);
