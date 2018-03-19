##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipam_mult_vul_sep_16.nasl 9116 2018-03-16 13:04:55Z cfischer $
#
# phpIPAM <= 1.2.1 Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107047");
  script_version("$Revision: 9116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-16 14:04:55 +0100 (Fri, 16 Mar 2018) $");
  script_tag(name:"creation_date", value:"2016-09-12 06:40:16 +0200 (Mon, 12 Sep 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("phpIPAM <= 1.2.1 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138603/PHPIPAM-1.2.1-Cross-Site-Scripting-SQL-Injection.html");
  script_xref(name:"URL", value:"https://phpipam.net/documents/changelog/");

  tag_insight = "phpIPAM version 1.2.1 suffers from cross site scripting and remote SQL injection vulnerabilities.";

  tag_impact = "Allows unauthorized disclosure of information; Allows unauthorized modification; Allows disruption of service .";

  tag_affected = "phpIPAM 1.2.1 and earlier.";

  tag_summary = "phpIPAM is prone to multiple vulnerabilities.";

  tag_solution = "Update to phpIPAM 1.3 or later, see http://phpipam.net for more information.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"1.2.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3 or later.");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );