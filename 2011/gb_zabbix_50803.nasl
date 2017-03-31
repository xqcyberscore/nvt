###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_50803.nasl 3386 2016-05-25 19:06:55Z jan $
#
# ZABBIX 'only_hostid' Parameter SQL Injection Vulnerability
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

tag_summary = "ZABBIX is prone to an SQL-injection vulnerability because it fails
to sufficiently sanitize user-supplied data before using it in an
SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

ZABBIX versions 1.8.3 and 1.8.4 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103348";
CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(50803);
 script_cve_id("CVE-2011-4674");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_version ("$Revision: 3386 $");

 script_name("ZABBIX 'only_hostid' Parameter SQL Injection Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50803");
 script_xref(name : "URL" , value : "http://www.zabbix.com/index.php");
 script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-4385");

 script_tag(name:"last_modification", value:"$Date: 2016-05-25 21:06:55 +0200 (Wed, 25 May 2016) $");
 script_tag(name:"creation_date", value:"2011-11-30 11:34:16 +0100 (Wed, 30 Nov 2011)");
 script_summary("Determine if installed Zabbix version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("zabbix_detect.nasl","zabbix_web_detect.nasl");
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
include("global_settings.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_equal(version: vers, test_version: "1.8.3") ||
     version_is_equal(version: vers, test_version: "1.8.4") ) {
      security_message(port:port);
      exit(0);
  }

}

exit(0);
