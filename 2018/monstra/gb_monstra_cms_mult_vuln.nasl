###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_monstra_cms_mult_vuln.nasl 10009 2018-05-29 14:09:04Z jschulte $
#
# Monstra CMS <= 3.0.4 Multiple Vulnerabilities
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113204");
  script_version("$Revision: 10009 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-29 16:09:04 +0200 (Tue, 29 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-29 16:04:31 +0200 (Tue, 29 May 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-11472", "CVE-2018-11473", "CVE-2018-11474", "CVE-2018-11475");

  script_name("Monstra CMS <= 3.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_monstra_cms_detect.nasl");
  script_mandatory_keys("monstra_cms/detected");

  script_tag(name:"summary", value:"Monstra CMS is prone to multile vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - Reflected XSS during Login (i.e., the login parameter to admin/index.php)

  - XSS in the registration Form (i.e., the login parameter to users/registration)

  - A password change at admin/index.php?id=users&action=edit&user_id=1 does not invalidate a session that is open in a different browser

  - A password change at users/1/edit does not invalidate a session that is open in a different browser");
  script_tag(name:"affected", value:"Monstra CMS through version 3.0.4.");
  script_tag(name:"solution", value:"No known solution is available as of 29th May, 2018.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/443");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/444");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/445");
  script_xref(name:"URL", value:"https://github.com/monstra-cms/monstra/issues/446");

  exit( 0 );
}

CPE = "cpe:/a:monstra:monstra";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.0.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "NoneAvailable" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
