##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_sec_bypass_vuln.nasl 5952 2017-04-13 12:34:17Z cfi $
#
# XOOPS Profiles Module Activation Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800777");
  script_version("$Revision: 5952 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-13 14:34:17 +0200 (Thu, 13 Apr 2017) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2009-4851");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("XOOPS Profiles Module Activation Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37274");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3256");
  script_xref(name:"URL", value:"http://www.xoops.org/modules/newbb/viewtopic.php?post_id=319132");

  tag_impact = "Successful exploitation will allow remote attackers to activate their accounts
  without requiring approval from the administrator.

  Impact Level: Application.";

  tag_affected = "XOOPS version prior to 2.4.1";

  tag_insight = "The flaw exists due to the error in the 'activate.php' script which does not
  verify the activation type when resending the activation email.";

  tag_solution = "Upgrade to the XOOPS version 2.4.1
  http://www.xoops.org/modules/core/";

  tag_summary = "This host is running XOOPS and is prone to security bypass
  vulnerability.";

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

## Check for the XOOPS version less than 2.4.1 (2.4.1 Final)
if( version_is_less( version:vers, test_version:"2.4.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.4.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
