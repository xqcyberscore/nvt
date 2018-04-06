# OpenVAS Vulnerability Test
# $Id: mantis_multiple_vulns4.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Mantis Multiple Flaws (4)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote web server contains a PHP application that is affected by
several flaws. 

Description :

According to its banner, the version of Mantis on the remote host fails
to sanitize user-supplied input to the 'g_db_type' parameter of the
'core/database_api.php' script.  Provided PHP's 'register_globals'
setting is enabled, an attacker may be able to exploit this to connect
to arbitrary databases as well as scan for arbitrary open ports, even on
an internal network.  In addition, it is reportedly prone to multiple
cross-site scripting issues.";

tag_solution = "Upgrade to Mantis 1.0.0rc2 or newer.";

#  Ref: vendor

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.19473");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(14604);
 script_cve_id("CVE-2005-2556","CVE-2005-2557", "CVE-2005-3090", "CVE-2005-3091"); 
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 name = "Mantis Multiple Flaws (4)";
 
 script_name(name);
 
 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");

 family = "Web application abuses";
 script_family(family);
 script_dependencies("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=112786017426276&w=2");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Try to exploit one of the flaws.
  req = http_get(
    item:string(
      dir, "/core/database_api.php?",
      # nb: request a bogus db driver.
      "g_db_type=", SCRIPT_NAME
    ), 
    port:port
  );
  debug_print("req='", req, "'.");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.");
  if( res == NULL ) exit(0);

  # There's a problem if the requested driver file is missing.
  #
  # nb: this message occurs even with PHP's display_errors disabled.
  if (
    "Missing file: " >< res &&
    string("/adodb/drivers/adodb-", SCRIPT_NAME, ".inc.php") >< res
  ) {
    security_message(port);
    exit(0);
  }

  # Check the version number since the XSS flaws occur independent of
  # register_globals while the exploit above requires it be enabled.
  if(ereg(pattern:"^(0\.19\.[0-3]|^1\.0\.0($|a[123]|rc1))", string:ver)) {
    report = string(
        "***** OpenVAS has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of Mantis\n",
        "***** installed there.\n");
    security_message(port:port, data:report);
    exit(0);
  }
}
