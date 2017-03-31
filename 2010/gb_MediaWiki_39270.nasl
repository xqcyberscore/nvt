###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_MediaWiki_39270.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# MediaWiki Cross Site Request Forgery Vulnerability
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

tag_summary = "MediaWiki is prone to a cross-site request-forgery vulnerability.

Exploiting this issue may allow a remote attacker to perform certain
administrative actions and gain unauthorized access to the affected
application. Other attacks are also possible.

Versions prior to MediaWiki 1.15.3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100568);
 script_version("$Revision: 5306 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
 script_bugtraq_id(39270);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("MediaWiki Cross Site Request Forgery Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39270");
 script_xref(name : "URL" , value : "http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-April/000090.html");
 script_xref(name : "URL" , value : "http://wikipedia.sourceforge.net/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_mediawiki_detect.nasl");
 script_require_ports("Services/www", 80);
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

if(!vers = get_kb_item(string("MediaWiki/Version")))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "1.15.3")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
