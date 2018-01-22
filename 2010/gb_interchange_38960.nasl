###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_interchange_38960.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# Interchange HTTP Response Splitting Vulnerability
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

tag_summary = "Interchange is prone to an HTTP response-splitting vulnerability.

Attackers can leverage this issue to influence or misrepresent how web
content is served, cached, or interpreted. This could aid in various
attacks that try to entice client users into a false sense of trust.

Interchange versions prior to 5.6.3 and 5.4.5 are vulnerable.";

tag_solution = "This issue has been addressed in Interchange 5.4.5 and 5.6.3.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100553");
 script_version("$Revision: 8457 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-03-25 19:45:44 +0100 (Thu, 25 Mar 2010)");
 script_bugtraq_id(38960);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("Interchange HTTP Response Splitting Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38960");
 script_xref(name : "URL" , value : "http://www.icdevgroup.org/i/dev/index.html");
 script_xref(name : "URL" , value : "http://www.icdevgroup.org/i/dev/news?mv_arg=00042");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_interchange_web_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"interchange")) {

  if(version_in_range(version: vers, test_version: "5.6", test_version2: "5.6.2") ||
     version_in_range(version: vers, test_version: "5.4", test_version2: "5.4.4")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
