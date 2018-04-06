###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mantis_49235.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# MantisBT Cross Site Scripting and SQL Injection Vulnerabilities
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

tag_summary = "MantisBT is prone to an SQL-injection vulnerability and a cross-site
scripting vulnerability.

Exploiting these issues could allow an attacker to steal cookie-
based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.

MantisBT 1.2.6 is vulnerable; other versions may also be affected.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103214");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-19 14:58:19 +0200 (Fri, 19 Aug 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-2938");
 script_bugtraq_id(49235);

 script_name("MantisBT Cross Site Scripting and SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49235");
 script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104149/mantisbt-sqlxss.txt");
 script_xref(name : "URL" , value : "http://www.mantisbt.org");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if(vers = get_version_from_kb(port:port,app:"mantis")) {

  if(version_is_equal(version: vers, test_version: "1.2.6")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
