###############################################################################
# OpenVAS Vulnerability Test
# $Id: flatpress_36543.nasl 4824 2016-12-21 08:49:38Z teissa $
#
# FlatPress 'userid' Parameter Local File Include Vulnerability
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

tag_summary = "FlatPress is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and execute arbitrary local scripts in the
context of the webserver process. This may allow the attacker to
compromise the application and the underlying computer; other attacks
are also possible.

FlatPress 0.804 through 0.812.1 are vulnerable.";


tag_solution = "The vendor has released an update. Please see the references
for details.";

if (description)
{
 script_id(100295);
 script_version("$Revision: 4824 $");
 script_tag(name:"last_modification", value:"$Date: 2016-12-21 09:49:38 +0100 (Wed, 21 Dec 2016) $");
 script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
 script_bugtraq_id(36543);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

 script_name("FlatPress 'userid' Parameter Local File Include Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36543");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53589");
 script_xref(name : "URL" , value : "https://sourceforge.net/project/shownotes.php?group_id=157089&release_id=628765");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/506816");

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("flatpress_detect.nasl");
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

if(!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/flatpress")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];
if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version: vers, test_version: "0.804", test_version2: "0.812.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
