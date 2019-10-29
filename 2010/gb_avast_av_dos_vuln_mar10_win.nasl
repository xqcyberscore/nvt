# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800479");
  script_version("2019-10-29T06:41:59+0000");
  script_tag(name:"last_modification", value:"2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0705");
  script_bugtraq_id(38363);
  script_name("Avast Antivirus 'aavmker4.sys' Denial Of Service Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509710/100/0/threaded");

  script_tag(name:"impact", value:"Successful exploitation will let the local attackers to cause a Denial of
  Service or gain escalated privileges on the victim's system.");

  script_tag(name:"affected", value:"Avast Antivirus Home and Professional version 4.8 to 4.8.1368.0 and
  avast! Home and Professional version 5.0 before 5.0.418.0 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an error in the 'aavmker4.sys' kernel driver when
  processing certain IOCTLs. This can be exploited to corrupt kernel memory via a specially crafted
  0xb2d60030 IOCTL.");

  script_tag(name:"solution", value:"Update to Avast Antivirus version 5.0.418 or later.");

  script_tag(name:"summary", value:"This host is installed with Avast AntiVirus and is prone to Denial
  Of Service vulnerability.");

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
fixed = "Update to Avast Antivirus version 5.0.418 or later";

if( version =~ "^4\.8" && version_in_range( version:version, test_version:"4.8.0", test_version2:"4.8.1368" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fixed, install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}
else if( version =~ "^5\.0" && version_in_range( version:version, test_version:"5.0", test_version2:"5.0.417" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fixed, install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
