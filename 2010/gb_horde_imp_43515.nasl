###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_imp_43515.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Horde IMP Webmail 'fetchmailprefs.php' HTML Injection Vulnerability
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

tag_summary = "Horde IMP Webmail is prone to an HTML-injection vulnerability because
it fails to sufficiently sanitize user-supplied data before it is used
in dynamic content.

Attacker-supplied HTML or JavaScript code could run in the context of
the affected site, potentially allowing the attacker to steal cookie-
based authentication credentials and to control how the site is
rendered to the user; other attacks are also possible.

Horde IMP 4.3.7 is affected; other versions may also be vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100826");
 script_version("$Revision: 8338 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-09-28 17:11:37 +0200 (Tue, 28 Sep 2010)");
 script_bugtraq_id(43515);
 script_cve_id("CVE-2010-3695", "CVE-2010-4778");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Horde IMP Webmail 'fetchmailprefs.php' HTML Injection Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43515");
 script_xref(name : "URL" , value : "http://www.horde.org/imp/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/513992");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("imp_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"imp")) {

  if(version_is_less_equal(version: vers, test_version: "4.3.7")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
