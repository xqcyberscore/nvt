###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_centreon_50568.nasl 3116 2016-04-19 10:11:19Z benallard $
#
# Centreon 'command_name' Parameter Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "Centreon is prone to a remote command-injection vulnerability.

Attackers can exploit this issue to execute arbitrary commands in the
context of the application.

Centreon 2.3.1 is affected; other versions may also be vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103338);
 script_bugtraq_id(50568);
 script_version ("$Revision: 3116 $");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_name("Centreon 'command_name' Parameter Remote Command Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50568");
 script_xref(name : "URL" , value : "http://www.centreon.com/");
 script_xref(name : "URL" , value : "https://www.trustwave.com/spiderlabs/advisories/TWSL2011-017.txt");

 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:11:19 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-11-16 09:31:56 +0100 (Wed, 16 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Determine if installed Cenreon version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("centreon_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"centreon")) {

  if(version_is_less_equal(version: vers, test_version: "2.3.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
