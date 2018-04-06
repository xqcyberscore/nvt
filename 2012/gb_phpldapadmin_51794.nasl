###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_51794.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# phpLDAPadmin 'server_id' Parameter Cross Site Scripting Vulnerabilities
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

tag_summary = "phpLDAPadmin is prone to cross-site scripting vulnerabilities because
it fails to properly sanitize user-supplied input.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

phpLDAPadmin 1.2.0.5-2 is affected; other versions may also be
vulnerable.";


if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103406");
 script_bugtraq_id(51794);
 script_version ("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("phpLDAPadmin 'server_id' Parameter Cross Site Scripting Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51794");
 script_xref(name : "URL" , value : "http://packages.debian.org/lenny/phpldapadmin");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521450");

 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-02 11:00:37 +0100 (Thu, 02 Feb 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("phpldapadmin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("phpldapadmin/installed");

 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"phpldapadmin"))exit(0);
url = string(dir, "/index.php?server_id=<script>alert('openvas-xss-test')</script>&redirect=false");

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",check_header:TRUE)) {

  security_message(port:port);
  exit(0);
}  

exit(0);
