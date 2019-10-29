# Copyright (C) 2010 SecPod
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
  script_oid("1.3.6.1.4.1.25623.1.0.902241");
  script_version("2019-10-29T06:41:59+0000");
  script_tag(name:"last_modification", value:"2019-10-29 06:41:59 +0000 (Tue, 29 Oct 2019)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3126");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Avast Antivirus File Opening Insecure Library Loading Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("avast/antivirus/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14743");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
  arbitrary code and conduct DLL hijacking attacks.");

  script_tag(name:"affected", value:"Avast Antivirus version 5.0.594 and prior.");

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
  libraries from the current working directory, which could allow attackers
  to execute arbitrary code by tricking a user into opening a license file.");

  script_tag(name:"solution", value:"Upgrade to Avast Antivirus version 5.0.677 or later.");

  script_tag(name:"summary", value:"This host is installed with Avast AntiVirus and is prone to
  insecure library loading vulnerability.");

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

if( version_is_less( version:version, test_version:"5.0.677" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.677", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
