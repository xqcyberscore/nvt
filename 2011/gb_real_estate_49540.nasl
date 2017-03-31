###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_real_estate_49540.nasl 3507 2016-06-14 04:32:30Z ckuerste $
#
# MYRE Real Estate Software 'findagent.php' Cross Site Scripting and SQL Injection Vulnerabilities
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

tag_summary = "MYRE Real Estate Software is prone to an SQL-injection and multiple
cross-site scripting vulnerabilities.

Exploiting these issues could allow an attacker to steal cookie-
based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.";


if (description)
{
 script_id(103250);
 script_version("$Revision: 3507 $");
 script_tag(name:"last_modification", value:"$Date: 2016-06-14 06:32:30 +0200 (Tue, 14 Jun 2016) $");
 script_tag(name:"creation_date", value:"2011-09-12 14:00:02 +0200 (Mon, 12 Sep 2011)");
 script_bugtraq_id(49540);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_name("MYRE Real Estate Software 'findagent.php' Cross Site Scripting and SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49540");
 script_xref(name : "URL" , value : "http://myrephp.com/");
 script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_MRS_SQL_XSS_Vuln.txt");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if MYRE Real Estate Software is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/realestate",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/findagent.php?country1=%3Cscript%3Ealert(/openvas-xss-test/)%3C/script%3E"); 

  if(http_vuln_check(port:port,url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",extra_check:"MYRE Real Estate Software", check_header:TRUE)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
