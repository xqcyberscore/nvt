###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mailspect_mult_vuln_06_14.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Mailspect Control Panel Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

tag_insight = "Mailspect Control Panel is prone to
1. a remote code execution (Authenticated)
2. two arbitrary file read (Authenticated)
3. a cross site scripting vulnerability (Unauthenticated)";

tag_impact = "An attacker can exploit these issues to obtain sensitive information
or to execute arbitrary script code or to execute arbitrary code in the context of
the application.";

tag_affected = "Mailspect Control Panel version 4.0.5";
tag_summary = "Mailspect Control Panel is prone to multiple vulnerabilities.";
tag_solution = "Ask the vendor for an update";
tag_vuldetect = "Send a crafted HTTP GET request and check the response";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105050");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_version ("$Revision: 6663 $");

 script_name("Mailspect Control Panel Multiple Vulnerabilities");


 script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/137");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-06-26 11:36:16 +0200 (Thu, 26 Jun 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 20001);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port( default:20001 );
if( ! get_port_state( port ) ) exit( 0 );

url = '/login.cgi?login=OpenVAS"><script>alert(/openvas-xss-test/)</script>';

if( http_vuln_check( port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE, extra_check:"<title>Login to Mailspect Control Panel" ) ) 
{
  security_message(port:port);
  exit(0);

}


exit(0);

