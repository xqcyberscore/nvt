###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rt_45959.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Request Tracker Password Information Disclosure Vulnerability
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

tag_summary = "Request Tracker is prone to an information-disclosure vulnerability
because it fails to securely store passwords.

Successful attacks can allow a local attacker to gain access to the
stored passwords.

Request Tracker 3.6.x and 3.8.x are affected; other versions may also
be vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103039");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 13:11:38 +0100 (Mon, 24 Jan 2011)");
 script_bugtraq_id(45959);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-0009");

 script_name("Request Tracker Password Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45959");
 script_xref(name : "URL" , value : "http://www.bestpractical.com/rt/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("rt_detect.nasl");
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

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"rt_tracker")) {

  if(version_in_range(version: vers, test_version: "3.6", test_version2: "3.6.7") ||
     version_in_range(version: vers, test_version: "3.8", test_version2: "3.8.8") ) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
