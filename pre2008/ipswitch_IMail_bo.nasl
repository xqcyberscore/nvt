###############################################################################
# OpenVAS Vulnerability Test
# $Id: ipswitch_IMail_bo.nasl 7506 2017-10-19 11:45:46Z cfischer $
#
# ipswitch IMail DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

CPE = "cpe:/a:ipswitch:imail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14684");
  script_version("$Revision: 7506 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-19 13:45:46 +0200 (Thu, 19 Oct 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2422", "CVE-2004-2423");
  script_bugtraq_id(11106);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ipswitch IMail DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_ipswitch_imail_server_detect.nasl");
  script_mandatory_keys("Ipswitch/IMail/detected");

  tag_summary = "The remote host is running IMail web interface. This version contains
  multiple buffer overflows.";

  tag_impact = "An attacker could use these flaws to remotly crash the service
  accepting requests from users, or possibly execute arbitrary code.";

  tag_solution = "Upgrade to IMail 8.13 or newer.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit(0);

if( version_is_less( version:version, test_version:"8.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.13" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
