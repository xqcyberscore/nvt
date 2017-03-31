###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_STHS_51991.nasl 3062 2016-04-14 11:03:39Z benallard $
#
# STHS v2 Web Portal 'team' parameter Multiple SQL Injection Vulnerabilities
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

tag_summary = "STHS v2 Web Portal is prone to multiple SQL-injection vulnerabilities
because the application fails to sufficiently sanitize user-supplied
data before using it in an SQL query.

Exploiting these issues could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

STHS v2 Web Portal 2.2 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(103421);
 script_bugtraq_id(51991);
 script_cve_id("CVE-2012-1217");
 script_version ("$Revision: 3062 $");

 script_name("STHS v2 Web Portal 'team' parameter Multiple SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51991");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73154");
 script_xref(name : "URL" , value : "http://www.simhl.net/");
 script_xref(name : "URL" , value : "http://0nto.wordpress.com/2012/02/13/sths-v2-web-portal-2-2-sql-injection-vulnerabilty/");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"last_modification", value:"$Date: 2016-04-14 13:03:39 +0200 (Thu, 14 Apr 2016) $");
 script_tag(name:"creation_date", value:"2012-02-15 11:22:27 +0100 (Wed, 15 Feb 2012)");
 script_summary("Determine if installed STHS is vulnerable");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/home.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Site powered by.*SIMHL.net")) {

    url = string(dir, "/prospects.php?team=-1%20union%20select%20openvas_sqli_test,saf,3,4,5,6,7,8,9,10,11,12");

    if(http_vuln_check(port:port, url:url,pattern:"Unknown column 'openvas_sqli_test' in 'field list'")) {
     
      security_message(port:port);
      exit(0);

    }

  }
}

exit(0);
