# OpenVAS Vulnerability Test
# $Id: basilix_arbitrary_file_disclosure.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: BasiliX Arbitrary File Disclosure Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

tag_summary = "The remote web server contains a PHP script that is prone to information
disclosure. 

Description :

The remote host appears to be running a BasiliX version 1.1.0 or lower. 
Such versions allow retrieval of arbitrary files that are accessible to
the web server user when sending a message since they accept a list of
attachment names from the client yet do not verify that the attachments
were in fact uploaded. 

Further, since these versions do not sanitize input to the 'login.php3'
script, it's possible for an attacker to establish a session on the
target without otherwise having access there by authenticating against
an IMAP server of his or her choosing.";

tag_solution = "Upgrade to BasiliX version 1.1.1 or later.";

if (description) {
  script_id(14305);
  script_version("$Revision: 6046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2002-1710");
  script_bugtraq_id(5062);

  name = "BasiliX Arbitrary File Disclosure Vulnerability";
  script_name(name);
 
 
  summary = "Checks for arbitrary file disclosure vulnerability in BasiliX";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0113.html");
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.(0.*|1\.0))$") {
    security_message(port);
    exit(0);
  }
}
