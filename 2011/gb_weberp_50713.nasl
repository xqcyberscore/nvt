###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_weberp_50713.nasl 3108 2016-04-19 06:58:41Z benallard $
#
# webERP Information Disclosure, SQL Injection, and Cross Site Scripting Vulnerabilities
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

tag_summary = "webERP is prone to information-disclosure, SQL-injection, and cross-
site scripting vulnerabilities because it fails to sufficiently
sanitize user-supplied input.

An attacker may exploit the information-disclosure issue to gain
access to sensitive information that may lead to further attacks.

An attacker may exploit the SQL-injection issue to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

An attacker may leverage the cross-site scripting issue to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may allow the attacker to steal cookie-
based authentication credentials and launch other attacks.

webERP 4.0.5 is vulnerable; prior versions may also be affected.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_id(103343);
 script_bugtraq_id(50713);
 script_version ("$Revision: 3108 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("webERP Information Disclosure, SQL Injection, and Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50713");
 script_xref(name : "URL" , value : "http://www.weberp.org/HomePage");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520561");
 script_xref(name : "URL" , value : "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_weberp.html");

 script_tag(name:"last_modification", value:"$Date: 2016-04-19 08:58:41 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-11-21 08:36:41 +0100 (Mon, 21 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed webERP is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
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

dirs = make_list("/weberp","/erp",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,'/AccountSections.php/%22%3E%3Cscript%3Ealert(/openvas-xss-test/);%3C/script%3E'); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\);</script>", check_header:TRUE)) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);

