###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_wac_server_bof_vuln.nasl 5478 2017-03-03 13:48:45Z cfi $
#
# Foxit WAC Server Buffer Overflow Vulnerability
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

CPE = "cpe:/a:foxitsoftware:wac_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900924");
  script_version("$Revision: 5478 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-03 14:48:45 +0100 (Fri, 03 Mar 2017) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7031");
  script_bugtraq_id(27873);
  script_name("Foxit WAC Server Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_foxit_wac_server_detect.nasl");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23);
  script_mandatory_keys("Foxit-WAC-Server/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/28272/");
  script_xref(name:"URL", value:"http://aluigi.org/adv/wachof-adv.txt");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/40608");

  tag_impact = "Successful exploitation will let the attackers execute arbitrary
  code and crash the application to cause denial of service.";

  tag_affected = "Foxit WAC Server 2.0 Build 3503 and prior on Windows.";

  tag_insight = "A heap-based buffer-overflow occurs in the 'wacsvr.exe' while
  processing overly long packets sent to SSH/Telnet ports.";

  tag_solution = "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.";

  tag_summary = "This host is running Foxit WAC Server and is prone to Buffer
  Overflow vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

# Grep for version 2.0.3503 and prior.
if( version_is_less_equal( version:vers, test_version:"2.0.3503" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );