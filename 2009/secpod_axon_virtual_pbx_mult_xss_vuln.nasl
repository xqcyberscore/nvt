###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_axon_virtual_pbx_mult_xss_vuln.nasl 4900 2017-01-02 09:13:30Z cfi $
#
# Axon Virtual PBX Multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:nch:axon_virtual_pbx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900984");
  script_version("$Revision: 4900 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 10:13:30 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4038");
  script_name("Axon Virtual PBX Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_axon_virtual_pbx_web_detect.nasl");
  script_require_ports("Services/www", 81);
  script_mandatory_keys("Axon-Virtual-PBX/www/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37157/");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/387986.php");

  tag_impact = "Successful exploitation will let the attackers execute arbitrary HTML and
  script code in the affected user's browser session.

  Impact Level: Application";

  tag_affected = "Axon Virtual PBX version 2.10 and 2.11";

  tag_insight = "The input passed into 'onok' and 'oncancel' parameters in the logon program
  is not properly sanitised before being returned to the user.";

  tag_solution = "Upgrade to Axon Virtual PBX version 2.13 or later
  For updates refer to http://www.nch.com.au/pbx/index.html";

  tag_summary = "This host has Axon Virtual PBX installed and is prone to Multiple XSS
  vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Check for Axon Virtual PBX version is 2.10 or 2.11
if( version_in_range( version:vers, test_version:"2.10", test_version2:"2.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.13" );
  security_message( port:port, data:report );
  exit( 0 );
}  

exit( 99 );
