##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_mod_proxy_ajp_info_disc_vuln.nasl 9218 2018-03-27 11:35:33Z cfischer $
#
# Apache mod_proxy_ajp Information Disclosure Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900499");
  script_version("$Revision: 9218 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-27 13:35:33 +0200 (Tue, 27 Mar 2018) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1191");
  script_bugtraq_id(34663);
  script_name("Apache mod_proxy_ajp Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34827");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50059");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=766938&r2=767089");
  script_xref(name:"URL", value:"https://archive.apache.org/dist/httpd/patches/apply_to_2.2.11/PR46949.diff");

  tag_affected = "Apache HTTP Versions prior to 2.2.15 running mod_proxy_ajp.";

  tag_impact = "Successful exploitation will let the attacker craft a special HTTP POST
  request and gain sensitive information about the web server.

  Impact level: Application";

  tag_insight = "This flaw is due to an error in 'mod_proxy_ajp' when handling
  improperly malformed POST requests.";

  tag_solution = "Upgrade to Apache HTTP Version 2.2.15 or later

  For further updates refer to http://httpd.apache.org/download.cgi

  Workaround:

  Update mod_proxy_ajp.c through SVN Repository (Revision 767089), see the references
  for a patch file containing an update.";

  tag_summary = "This host is running Apache Web Server and is prone to
  Information Disclosure Vulnerability.";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.15" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );