###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coremail_stored_xss_vuln.nasl 9921 2018-05-22 13:02:25Z jschulte $
#
# Coremail XT <= 3.0 Stored XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113192");
  script_version("$Revision: 9921 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-22 15:02:25 +0200 (Tue, 22 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-22 14:52:35 +0200 (Tue, 22 May 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-9330");

  script_name("Coremail XT <= 3.0 Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_coremailxt_detect.nasl");
  script_mandatory_keys("coremail/detected");

  script_tag(name:"summary", value:"Coremail XT is vulnerable to a stored Cross-Site-Scripting (XSS) Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability exists within the third form field in a URI under register/.");
  script_tag(name:"impact", value:"Successful exploitation would allow to permanently modify the site's content,
  including injection of malicious code.");
  script_tag(name:"affected", value:"Coremail XT through version 3.0.");
  script_tag(name:"solution", value:"No known solution is available as of 22nd May, 2018.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.youtube.com/watch?v=LRK3c_DhXn4");
  script_xref(name:"URL", value:"http://www.coremail.cn/");

  exit( 0 );
}

CPE = "cpe:/a:mailtech:coremail";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "NoneAvailable" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
