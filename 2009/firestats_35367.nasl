###############################################################################
# OpenVAS Vulnerability Test
# $Id: firestats_35367.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# FireStats 'firestats-wordpress.php' Remote File Include
# Vulnerability
#
# Authors
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

tag_summary = "FireStats is prone to a remote file-include vulnerability because it
  fails to sufficiently sanitize user-supplied data.

  Exploiting this issue may allow an attacker to compromise the
  application and the underlying system; other attacks are also
  possible.

  FireStats 1.6.1 is vulnerable; prior versions may also be affected.";

tag_solution = "The vendor has released 'FireStats 1.6.2' to address this issue. See
  http://firestats.cc/ for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100227");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-06-21 16:51:00 +0200 (Sun, 21 Jun 2009)");
 script_cve_id("CVE-2009-2143");
 script_bugtraq_id(35367);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("FireStats 'firestats-wordpress.php' Remote File Include Vulnerability");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("firestats_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35367");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/FireStats")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

version  = matches[1];

if( ! isnull(version)) {

  if(version_is_less(version: version, test_version: "1.6.2")) {

    security_message(port: port);
    exit(0);

  }  

}  

exit(0);
