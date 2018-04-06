###############################################################################
# OpenVAS Vulnerability Test
# $Id: pligg_37185.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Pligg Cross Site Scripting And Request Forgery Remote Vulnerabilities
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

tag_summary = "Pligg is prone to multiple cross-site scripting vulnerabilities and a
cross-site request-forgery vulnerability.

An attacker can exploit these issues to steal cookie-based
authentication credentials or perform unauthorized actions when
masquerading as the victim. Other attacks are also possible.

Versions prior to Pligg 1.0.3 are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100375");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)");
 script_cve_id("CVE-2009-4786", "CVE-2009-4787", "CVE-2009-4788");
 script_bugtraq_id(37185);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("Pligg Cross Site Scripting And Request Forgery Remote Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37185");
 script_xref(name : "URL" , value : "http://holisticinfosec.org/content/view/130/45/");
 script_xref(name : "URL" , value : "http://www.pligg.com/blog/775/pligg-cms-1-0-3-release/");
 script_xref(name : "URL" , value : "http://www.pligg.com/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("pligg_cms_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/pligg")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "1.0.3")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
