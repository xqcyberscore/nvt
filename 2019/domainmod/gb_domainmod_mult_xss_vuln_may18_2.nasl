###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_domainmod_mult_xss_vuln_may18_2.nasl 13260 2019-01-24 09:34:34Z jschulte $
#
# DomainMOD <= 4.10.0 Multiple XSS Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113329");
  script_version("$Revision: 13260 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 10:34:34 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-23 14:38:54 +0200 (Wed, 23 Jan 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-11558", "CVE-2018-11559");

  script_name("DomainMOD <= 4.10.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_domainmod_http_detect.nasl");
  script_mandatory_keys("domainmod/detected");

  script_tag(name:"summary", value:"DomainMOD is prone to multiple Cross-Site Scripting (XSS) Vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Stored XSS in the '/settings/profile/index.php' new_first_name parameter

  - Stored XSS in the '/settings/profile/index.php' new_last_name parameter");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to inject
  arbitrary JavaScript and HTML into the page.");
  script_tag(name:"affected", value:"DomainMOD through version 4.10.0.");
  script_tag(name:"solution", value:"No known solution is available as of 23rd January, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/66");

  exit(0);
}

CPE = "cpe:/a:domainmod:domainmod";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "4.10.00" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
