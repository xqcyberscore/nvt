###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sit_50742.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Support Incident Tracker 'translate.php' Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "Support Incident Tracker is prone to a remote code-execution
vulnerability because the application fails to sufficiently sanitize
user-supplied input.

Exploiting this issue will allow attackers to execute arbitrary PHP
code within the context of the affected application.

Support Incident Tracker 3.45 to 3.65 is vulnerable; prior versions
may also be affected.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103349");
 script_bugtraq_id(50742);
 script_version ("$Revision: 9351 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Support Incident Tracker 'translate.php' Remote Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50742");
 script_xref(name : "URL" , value : "http://sitracker.sourceforge.net");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520577");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-11-30 11:40:15 +0100 (Wed, 30 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("support_incident_tracker_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"support_incident_tracker")) {
  if(version_in_range(version: vers, test_version: "3.45", test_version2: "3.65")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
