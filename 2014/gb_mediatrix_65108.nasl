###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediatrix_65108.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Mediatrix 4402 Web Management Interface 'login' Page Cross Site Scripting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103900";

tag_insight = "Reflected cross-site scripting (XSS) vulnerability in
Mediatrix Web Management Interface, found in the login page, allows
remote attackers to inject arbitrary web scripts or HTML via the
vulnerable parameter 'username'";

tag_impact = "An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.";

tag_affected = "Mediatrix 4402 running firmware Dgw 1.1.13.186 is vulnerable; other
versions may also be affected.";

tag_summary = "Mediatrix 4402 is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.";

tag_solution = "Ask the Vendor for an update.";

tag_vuldetect = "Send a special crafted HTTP request and check the
response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(65108);
 script_cve_id("CVE-2014-1612");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version ("$Revision: 6769 $");

 script_name("Mediatrix 4402 Web Management Interface 'login' Page Cross Site Scripting Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65108");
 
 script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-02-04 14:02:25 +0100 (Tue, 04 Feb 2014)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("Mbedthis-Appweb/banner");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( "Mbedthis-Appweb" >!< banner ) exit (0);

if( http_vuln_check( port:port, url:'/login.esp', pattern:"<title>Mediatrix</title>|Media5 Corporation" ) )
{
  url = '/login.esp?r=system_info.esp&username="/><script>alert(/openvas-xss-test/)</script>';
  if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE ) )
  {  
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99) ;

