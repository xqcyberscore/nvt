###############################################################################
# OpenVAS Vulnerability Test
# $Id: barracuda_im_firewall_37248.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Barracuda IM Firewall 'smtp_test.cgi' Cross-Site Scripting Vulnerabilities
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

tag_summary = "Barracuda IM Firewall is prone to multiple cross-site scripting
vulnerabilities because the application fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may help the attacker steal cookie-based authentication
credentials and launch other attacks.

Barracuda IM Firewall 620 Firmware v4.0.01.003 is vulnerable; other
versions may also be affected.";


if (description)
{
 script_id(100393);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-12-11 12:55:06 +0100 (Fri, 11 Dec 2009)");
 script_bugtraq_id(37248);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("Barracuda IM Firewall 'smtp_test.cgi' Cross-Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37248");
 script_xref(name : "URL" , value : "http://www.barracudanetworks.com/ns/products/im_overview.php");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("barracuda_im_firewall_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("www/", port, "/barracuda_im_firewall")))exit(0);

if(!isnull(version) && version >!< "unknown") {

  if(version_is_equal(version: version, test_version: "4.0.01.003")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
