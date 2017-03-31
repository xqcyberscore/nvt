###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SquirrelMail_42399.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# SquirrelMail Remote Denial of Service Vulnerability
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

tag_summary = "SquirrelMail is prone to a remote denial-of-service vulnerability
because it fails to properly handle certain user requests.

An attacker can exploit this issue to cause the application to consume
excessive disk space, resulting in denial-of-service conditions.

SquirrelMail versions prior and up to 1.4.20 are vulnerable; others
may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100759);
 script_version("$Revision: 5373 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-13 12:44:16 +0200 (Fri, 13 Aug 2010)");
 script_bugtraq_id(42399);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2813");

 script_name("SquirrelMail Remote Denial of Service Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42399");
 script_xref(name : "URL" , value : "http://www.squirrelmail.org/");
 script_xref(name : "URL" , value : "http://www.squirrelmail.org/security/issue/2010-07-23");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=618096");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("squirrelmail_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"squirrelmail")) {

  if(version_is_less(version: vers, test_version: "1.4.21")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);

