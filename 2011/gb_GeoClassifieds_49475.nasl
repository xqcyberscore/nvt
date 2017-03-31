###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_GeoClassifieds_49475.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# GeoClassifieds Lite Multiple Cross Site Scripting and SQL Injection Vulnerabilities
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

tag_summary = "GeoClassifieds Lite is prone to multiple SQL-injection and cross-site
scripting vulnerabilities.

Exploiting these issues could allow an attacker to steal cookie-
based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.

GeoClassifieds Lite 2.0.1, 2.0.3.1, 2.0.3.2 and 2.0.4 are vulnerable;
other versions may also be affected.";


if (description)
{
 script_id(103270);
 script_version("$Revision: 3117 $");
 script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
 script_tag(name:"creation_date", value:"2011-09-22 13:43:24 +0200 (Thu, 22 Sep 2011)");
 script_bugtraq_id(49475);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("GeoClassifieds Lite Multiple Cross Site Scripting and SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49475");
 script_xref(name : "URL" , value : "http://www.geodesicsolutions.com/");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed GeoClassifieds is vulnerable");
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

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php?a=19&c=</div><script>alert(/openvas-xss-test/);</script>"); 

  if(http_vuln_check(port:port,url:url,pattern:"<script>alert\(/openvas-xss-test/\);</script>",check_header:TRUE,extra_check:"powered by GeoClassifieds")) {
     
    security_message(port:port);
    exit(0);

  }
}

exit(0);
