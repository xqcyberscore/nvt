# OpenVAS Vulnerability Test
# $Id: vbulletin_init_php_flaw.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: vBulletin Init.PHP unspecified vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host is running vBulletin, a web based bulletin board system written
in PHP.

The remote version of this software is vulnerable to an unspecified issue. It is 
reported that versions 3.0.0 through to 3.0.4 are prone to a security flaw 
in 'includes/init.php'. Successful exploitation requires that 'register_globals' 
is enabled.

*** As OpenVAS solely relied on the banner of the remote host
*** this might be a false positive";

tag_solution = "Upgrade to vBulletin 3.0.5 or newer";

#  Ref: vBulletin team

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16203");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12299);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "vBulletin Init.PHP unspecified vulnerability";
 script_name(name);
 


 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl", "vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("vBulletin/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/13901/");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if ( ver =~ '3.0(\\.[0-4])?[^0-9]' ) security_message(port);
}
