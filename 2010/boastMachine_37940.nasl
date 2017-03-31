###############################################################################
# OpenVAS Vulnerability Test
# $Id: boastMachine_37940.nasl 5245 2017-02-09 08:57:08Z teissa $
#
# boastMachine Arbitrary File Upload Vulnerability
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

tag_summary = "boastMachine is prone to a vulnerability that lets attackers upload
arbitrary files because the application fails to adequately sanitize
user-supplied input.

An attacker can exploit this vulnerability to upload arbitrary code
and run it in the context of the webserver process. This may
facilitate unauthorized access or privilege escalation; other attacks
are also possible.

boastMachine 3.1 is affected; other versions may be vulnerable as
well.";


if (description)
{
 script_id(100461);
 script_version("$Revision: 5245 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-09 09:57:08 +0100 (Thu, 09 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-01-25 18:49:48 +0100 (Mon, 25 Jan 2010)");
 script_bugtraq_id(37940);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("boastMachine Arbitrary File Upload Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37940");
 script_xref(name : "URL" , value : "http://boastology.com/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("boastMachine_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/boastMachine")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less_equal(version: vers, test_version: "3.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
