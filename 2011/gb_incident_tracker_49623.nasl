###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_incident_tracker_49623.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Support Incident Tracker (SiT!) Multiple Input Validation Vulnerabilities
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

tag_summary = "Support Incident Tracker (SiT!) is prone to the following input-
validation vulnerabilities:

1. Multiple cross-site scripting vulnerabilities
2. Multiple SQL-injection vulnerabilities
3. Multiple cross-site request-forgery vulnerabilities

Exploiting these issues could allow an attacker to execute arbitrary
code, steal cookie-based authentication credentials, compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Support Incident Tracker (SiT!) 3.64 is vulnerable; other versions may
also be affected.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103257");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-15 12:51:05 +0200 (Thu, 15 Sep 2011)");
 script_bugtraq_id(49623);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Support Incident Tracker (SiT!) Multiple Input Validation Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49623");
 script_xref(name : "URL" , value : "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_sit_support_incident_tracker.html");
 script_xref(name : "URL" , value : "http://sitracker.sourceforge.net");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519636");
 script_xref(name : "URL" , value : "http://sitracker.org/wiki/ReleaseNotes365");

 script_tag(name:"qod_type", value:"remote_active");
 script_category(ACT_ATTACK);
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

if(!can_host_php(port:port))exit(0);

if( ! dir = get_dir_from_kb(port:port,app:"support_incident_tracker"))exit(0);
url = string(dir, "/portal/kb.php?start=%27"); 

if(http_vuln_check(port:port, url:url,pattern:"You have an error in your SQL syntax")) {
     
  security_message(port:port);
  exit(0);

}

exit(0);

