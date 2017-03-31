###############################################################################
# OpenVAS Vulnerability Test
# $Id: cacti_37137.nasl 4574 2016-11-18 13:36:58Z teissa $
#
# Cacti 'Linux - Get Memory Usage' Remote Command Execution Vulnerability
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

tag_summary = "Cacti is prone to a remote command-execution vulnerability because the
software fails to adequately sanitize user-supplied input.

Successful attacks can compromise the affected software and possibly
the computer.";


if (description)
{
 script_id(100365);
 script_version("$Revision: 4574 $");
 script_tag(name:"last_modification", value:"$Date: 2016-11-18 14:36:58 +0100 (Fri, 18 Nov 2016) $");
 script_tag(name:"creation_date", value:"2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)");
 script_bugtraq_id(37137);
 script_cve_id("CVE-2009-4112");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

 script_name("Cacti 'Linux - Get Memory Usage' Remote Command Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37137");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2009-11/0292.html");
 script_xref(name : "URL" , value : "http://cacti.net/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/cacti")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "0.8.7e")) {
     security_message(port:port);
     exit(0);
   }  

} 

exit(0);
