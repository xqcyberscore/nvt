###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openaudit_40315.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# Open-Audit Multiple Vulnerabilities
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

tag_summary = "Open-Audit is prone to multiple vulnerabilities, including a local file-
include vulnerability and multiple SQL-injection, cross-site
scripting, and authentication-bypass vulnerabilities.

An attacker can exploit these vulnerabilities to steal cookie-based
authentication credentials, compromise the application, access or
modify data, exploit latent vulnerabilities in the underlying
database, bypass security restrictions, obtain potentially sensitive
information, perform unauthorized actions, or execute arbitrary local
scripts in the context of the webserver process; other attacks are
also possible.

Open-Audit 20081013 and 20091223-RC are vulnerable; other versions may
also be affected.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100654");
 script_version("$Revision: 8440 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)");
 script_bugtraq_id(40315);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Open-Audit Multiple Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40315");
 script_xref(name : "URL" , value : "http://www.open-audit.org/index.php");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/open-audit", "/openaudit", "/open_audit", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( buf == NULL )continue;

  if( "<title>Open-AudIT</title>" >< buf ) {

    url = string(dir,"/list.php?view=%3Cscript%3Ealert(%27OpenVAS-XSS-Test%27)%3B%3C%2Fscript%3E");

    if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('OpenVAS-XSS-Test'\);</script>", check_header:TRUE)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
