###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpgroupware_html_injection2.nasl 5613 2017-03-20 10:08:39Z cfi $
#
# PhpGroupWare index.php HTML injection vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:phpgroupware:phpgroupware";

# Ref: Cedric Cochin <cco@netvigilance.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16138");
  script_version("$Revision: 5613 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 11:08:39 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2574");
  script_bugtraq_id(12082);
  script_xref(name:"OSVDB", value:"7599");
  script_xref(name:"OSVDB", value:"7600");
  script_xref(name:"OSVDB", value:"7601");
  script_xref(name:"OSVDB", value:"7602");
  script_xref(name:"OSVDB", value:"7603");
  script_xref(name:"OSVDB", value:"7604");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("PhpGroupWare index.php HTML injection vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpGroupWare/installed");

  script_xref(name:"URL", value:"http://www.phpgroupware.org/");

  tag_summary = "The remote host seems to be running PhpGroupWare, a multi-user groupware
  suite written in PHP.";

  tag_insight = "This version has been reported prone to HTML injection vulnerabilities
  through 'index.php'. These issues present themself due to a lack of
  sufficient input validation performed on form fields used by
  PHPGroupWare modules.";

  tag_impact = "A malicious attacker may inject arbitrary HTML and script code using
  these form fields that may be incorporated into dynamically generated web content.";

  tag_solution = "Update to version 0.9.16 RC3 or newer";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"insight", value:tag_insight);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/phpsysinfo/inc/hook_admin.inc.php";

if( http_vuln_check( port:port, url:url, pattern:".*Fatal error.* in <b>/.*" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
