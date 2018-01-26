###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orangehrm_43905.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# OrangeHRM 'uri' Parameter Local File Include Vulnerability
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

tag_summary = "OrangeHRM is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information or to execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the computer; other attacks are
also possible.

OrangeHRM 2.6.0.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100851");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4798");
 script_bugtraq_id(43905);

 script_name("OrangeHRM 'uri' Parameter Local File Include Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43905");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/orangehrm/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_orangehrm_detect.nasl");
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

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"orangehrm")) {

  if(version_is_equal(version: vers, test_version: "2.6.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
