# OpenVAS Vulnerability Test
# $Id: mantis_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Mantis multiple unspecified XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Netwok Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote web server contains a PHP application that is prone
to cross-site scripting attacks.

Description :

According to its banner, the remote version of Mantis contains a flaw
in the handling of some types of input.  Because of this, an attacker
may be able to cause arbitrary HTML and script code to be executed in
a user's browser within the security context of the affected web site.";

tag_solution = "Upgrade to Mantis 0.18.1 or newer.";

#  Ref: Paul Richards

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14344");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(9184);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 name = "Mantis multiple unspecified XSS";
 
 script_name(name);
 


 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=202559");
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if(ereg(pattern:"^0\.([0-9]\.|1[0-7]\.|18\.0[^0-9])", string:ver))
	security_message(port);
}
