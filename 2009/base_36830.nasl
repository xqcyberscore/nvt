###############################################################################
# OpenVAS Vulnerability Test
# $Id: base_36830.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Basic Analysis and Security Engine Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Updated By Sooraj KS <kssooraj@secpod.com>
# date update: 2010/05/14
# Added CVE-2009-4837  CVE-2009-4838  CVE-2009-4839 and BID 18298
#
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

tag_summary = "Basic Analysis and Security Engine (BASE) is prone to multiple input-
validation vulnerabilities because it fails to adequately sanitize user-
supplied input. These vulnerabilities include an SQL-injection issue,
a cross-site scripting issue, and a local file-include issue.

Exploiting these issues can allow an attacker to steal cookie-based
authentication credentials, view and execute local files within the
context of the webserver, compromise the application, access or modify
data, or exploit latent vulnerabilities in the underlying database.
Other attacks may also be possible.

These issues affect versions prior to BASE 1.4.4.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100323);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
 script_bugtraq_id(36830,18298);
 script_cve_id("CVE-2009-4590", "CVE-2009-4591", "CVE-2009-4592","CVE-2009-4837","CVE-2009-4838","CVE-2009-4839");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Basic Analysis and Security Engine Multiple Input Validation Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36830");
 script_xref(name : "URL" , value : "http://secureideas.sourceforge.net/");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("base_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("BASE/installed");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/BASE")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "1.4.4")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
