###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axigen_43230.nasl 5263 2017-02-10 13:45:51Z teissa $
#
# Axigen Webmail Directory Traversal Vulnerability
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

tag_summary = "Axigen Webmail is prone to a directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Axigen Webmail 7.4.1 is vulnerable; other versions may be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(100805);
 script_version("$Revision: 5263 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:45:51 +0100 (Fri, 10 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-09-15 18:43:03 +0200 (Wed, 15 Sep 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2010-3459", "CVE-2010-3460");
 script_bugtraq_id(43230);

 script_name("Axigen Webmail Directory Traversal Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43230");
 script_xref(name : "URL" , value : "http://www.axigen.com/");
 script_xref(name : "URL" , value : "http://www.axigen.com/press/product-releases/axigen-releases-version-742_74.html");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("axigen_web_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:8888);
if(!get_port_state(port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"axigen"))exit(0);
   
url = string(dir, "/..%5c..%5crun/axigen.cfg"); 

if(http_vuln_check(port:port, url:url, pattern:"Server {", check_header: TRUE, extra_check: make_list("Server: Axigen-Webmail","sslRandomFile","listeners"))) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

