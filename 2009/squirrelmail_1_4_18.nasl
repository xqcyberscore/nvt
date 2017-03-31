###############################################################################
# OpenVAS Vulnerability Test
# $Id: squirrelmail_1_4_18.nasl 5220 2017-02-07 11:42:33Z teissa $
#
# SquirrelMail Prior to 1.4.18 Multiple Vulnerabilities
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

tag_summary = "SquirrelMail is prone to multiple vulnerabilities, including
  multiple session-fixation issues, a code-injection issue, and
  multiple cross-site scripting issues.

  Attackers may exploit these issues to execute arbitrary script code
  in the browser of an unsuspecting user, to hijack the session of a
  valid user, or to inject and execute arbitrary PHP code in the
  context of the webserver process. This may facilitate a compromise
  of the application and the computer; other attacks are also
  possible.

  Versions prior to SquirrelMail 1.4.18 are vulnerable.";


if (description)
{
 script_id(100203);
 script_version("$Revision: 5220 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-07 12:42:33 +0100 (Tue, 07 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-05-14 20:19:12 +0200 (Thu, 14 May 2009)");
 script_bugtraq_id(34916);
 script_cve_id("CVE-2009-1578","CVE-2009-1579","CVE-2009-1580","CVE-2009-1581");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("SquirrelMail Prior to 1.4.18 Multiple Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("squirrelmail_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34916");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/squirrelmail")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less_equal(version: vers, test_version: "1.4.18")) {
      security_message(port:port);
      exit(0);
  }  

} 

exit(0);
