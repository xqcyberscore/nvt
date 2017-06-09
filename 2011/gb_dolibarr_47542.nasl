###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_47542.nasl 6127 2017-05-15 12:07:00Z cfi $
#
# Dolibarr Local File Include and Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103144");
  script_version("$Revision: 6127 $");
  script_bugtraq_id(47542);
  script_tag(name:"last_modification", value:"$Date: 2017-05-15 14:07:00 +0200 (Mon, 15 May 2017) $");
  script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Dolibarr Local File Include and Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Dolibarr/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47542");
  script_xref(name:"URL", value:"http://www.dolibarr.org/downloads/cat_view/62-stables-versions");
  script_xref(name:"URL", value:"http://www.dolibarr.org/");

  tag_summary = "Dolibarr is prone to a local file-include vulnerability and a cross-
  site scripting vulnerability because it fails to properly sanitize user-
  supplied input.";

  tag_impact = "An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute local files within
  the context of the affected application. Information harvested may
  aid in further attacks.

  The attacker may leverage the cross-site scripting issues to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal cookie-
  based authentication credentials and launch other attacks.";

  tag_affected = "Dolibarr 3.0.0 is vulnerable; other versions may also be affected.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = string( dir, "/document.php?lang=%22%3E%3Cscript%3Ealert%28%27openvas-xss-test%27%29%3C/script%3E" ); 

if( http_vuln_check( port:port, url:url, pattern:"<script>alert\('openvas-xss-test'\)</script>", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );