###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orion_npm_45257.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# SolarWinds Orion Network Performance Monitor (NPM) Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

tag_summary = "SolarWinds Orion NPM is prone to multiple cross-site-scripting
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

SolarWinds Orion Network Performance Monitor (NPM) 10.1 is vulnerable;
other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100941");
 script_version("$Revision: 8469 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)");
 script_cve_id("CVE-2010-4828");
 script_bugtraq_id(45257);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_name("SolarWinds Orion Network Performance Monitor (NPM) Multiple Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45257");
 script_xref(name : "URL" , value : "http://www.solarwinds.com/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_orion_npm_detect.nasl");
 script_require_ports("Services/www", 8787);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_asp(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"orion_npm")) {

  if(version_is_equal(version: vers, test_version: "10.1")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
