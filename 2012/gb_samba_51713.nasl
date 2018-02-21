###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_51713.nasl 8882 2018-02-20 10:35:37Z cfischer $
#
# Samba Memory Leak Local Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103411");
  script_version ("$Revision: 8882 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-20 11:35:37 +0100 (Tue, 20 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-02-09 10:12:15 +0100 (Thu, 09 Feb 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(51713);
  script_cve_id("CVE-2012-0817");
  script_name("Samba Memory Leak Local Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51713");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2012-0817");
  script_xref(name:"URL", value:"http://www.samba.org");

  tag_summary = "Samba is prone to a local denial-of-service vulnerability.";

  tag_impact = "A local attacker can exploit this issue to exhaust available memory,
  denying access to legitimate users.";

  tag_affected = "The vulnerability affects Samba versions 3.6.0 through 3.6.2.";

  tag_solution = "Updates are available. Please see the references for details.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.6", test_version2:"3.6.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.6.3");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
