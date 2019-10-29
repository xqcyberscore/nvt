# Copyright (C) 2009 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:avast:antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801111");
  script_version("2019-10-29T06:41:59+0000");
  script_tag(name:"last_modification", value:"2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3522", "CVE-2009-3523", "CVE-2009-3524");
  script_bugtraq_id(36507);
  script_name("avast! Multiple Vulnerabilities - Oct09 (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36858/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/506681");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2761");

  script_tag(name:"impact", value:"Successful exploitation will let the local attackers to cause a Denial of
  Service or gain escalated privileges on the victim's system.");

  script_tag(name:"affected", value:"avast! Home and Professional version prior to 4.8.1356 on Windows.");

  script_tag(name:"insight", value:"- A boundary error exists in the 'aswMon2' kernel driver when processing
  IOCTLs. This can be exploited to cause a stack-based buffer overflow via a specially crafted 0xB2C80018 IOCTL.

  - An error in the 'AavmKer4.sys' kernel driver that can be exploited to
  corrupt memory via a specially crafted 0xB2D6000C or 0xB2D60034 IOCTL.

  - An unspecified error exists in the ashWsFtr.dll library which can be
  exploited to cause unknown impact.");

  script_tag(name:"solution", value:"Upgrade to avast! version 4.8.1356 or later.");

  script_tag(name:"summary", value:"This host is installed with avast! AntiVirus and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"4.8.1356" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.8.1356", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
