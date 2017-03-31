###############################################################################
# OpenVAS Vulnerability Test
# $Id: AfterLogic_WebMail_Pro_36605.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# AfterLogic WebMail Pro Multiple Cross Site Scripting Vulnerabilities
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

tag_summary = "AfterLogic WebMail Pro is prone to multiple cross-site scripting
vulnerabilities because the application fails to sufficiently sanitize
user-supplied data.

Attacker-supplied HTML or JavaScript code could run in the context of
the affected site, potentially allowing the attacker to steal cookie-
based authentication credentials; other attacks are also possible.

AfterLogic WebMail Pro 4.7.10 and prior versions are affected.";


tag_solution = "Reports indicate that the vendor addressed these issues in WebMail Pro
4.7.11, but Symantec has not confirmed this. Please contact the vendor
for more information.";

if (description)
{
 script_id(100314);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-10-20 18:54:22 +0200 (Tue, 20 Oct 2009)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2009-4743");
 script_bugtraq_id(36605);

 script_name("AfterLogic WebMail Pro Multiple Cross Site Scripting Vulnerabilities");


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("AfterLogic_WebMail_Pro_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36605");
 script_xref(name : "URL" , value : "http://www.afterlogic.com/");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port) && !can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/AfterLogicWebMailPro")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "4.7.10")) {
      security_message(port:port);
      exit(0);
  }
}

exit(0);
