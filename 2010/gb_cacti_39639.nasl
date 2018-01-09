###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_39639.nasl 8314 2018-01-08 08:01:01Z teissa $
#
# Cacti Multiple Input Validation Security Vulnerabilities
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

tag_summary = "Cacti is prone to multiple input-validation vulnerabilities because it
fails to adequately sanitize user-supplied input. These
vulnerabilities include SQL-injection and command-injection issues.

Exploiting these issues can allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database. Other attacks may also be possible.

Cacti 0.8.7e is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available to address the SQL-injection issue. Please see
the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100599");
 script_version("$Revision: 8314 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
 script_cve_id("CVE-2010-1431");
 script_bugtraq_id(39639);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Cacti Multiple Input Validation Security Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39639");
 script_xref(name : "URL" , value : "http://cacti.net/");
 script_xref(name : "URL" , value : "http://www.bonsai-sec.com/en/research/vulnerabilities/cacti-os-command-injection-0105.php");
 script_xref(name : "URL" , value : "http://www.bonsai-sec.com/en/research/vulnerabilities/cacti-sql-injection-0104.php");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("cacti_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"cacti")) {

  if(version_is_less(version: vers, test_version: "0.8.7e")) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
