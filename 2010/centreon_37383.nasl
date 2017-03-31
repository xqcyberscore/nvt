###############################################################################
# OpenVAS Vulnerability Test
# $Id: centreon_37383.nasl 5245 2017-02-09 08:57:08Z teissa $
#
# Centreon Authentication Mechanism Security Bypass Vulnerability
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

tag_summary = "Centreon is prone to a security-bypass vulnerability.

An attacker can exploit this issue to bypass certain security
restrictions and gain unauthorized access to certain functionality,
which may lead to further attacks.

Versions prior to Centreon 2.1.4 are vulnerable.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100428);
 script_version("$Revision: 5245 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-09 09:57:08 +0100 (Thu, 09 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-01-06 10:44:19 +0100 (Wed, 06 Jan 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2009-4368");
 script_bugtraq_id(37383);

 script_name("Centreon Authentication Mechanism Security Bypass Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37383");
 script_xref(name : "URL" , value : "http://www.centreon.com/Development/changelog-2x.html");
 script_xref(name : "URL" , value : "http://www.centreon.com/");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("centreon_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/centreon")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.1.4")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
