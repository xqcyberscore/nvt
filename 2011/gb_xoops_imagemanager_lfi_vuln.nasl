###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_imagemanager_lfi_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# XOOPS 'imagemanager.php' Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801932");
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_bugtraq_id(47418);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("XOOPS 'imagemanager.php' Local File Inclusion Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://dl.packetstormsecurity.net/1104-exploits/xoops250-lfi.txt");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2011/04/18/webapps-0day-xoops-2-5-0-imagemanager-php-lfi-vulnerability-2/");

  tag_impact = "Successful exploitation could allow attackers to perform file
  inclusion attacks and read arbitrary files on the affected application.

  Impact Level: Application";

  tag_affected = "XOOPS version 2.5.0 and prior.";

  tag_insight = "The flaw is due to input validation error in 'target' parameter
  to 'imagemanager.php', which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.";

  tag_solution = "Upgrade to version 2.5.1 or later,
  For updates refer to http://sourceforge.net/projects/xoops";

  tag_summary = "This host is running with XOOPS and is prone to local file
  inclusion vulnerability.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected" , value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for the XOOPS version less or equal 2.5.0
if( version_is_less_equal( version:vers, test_version:"2.5.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
