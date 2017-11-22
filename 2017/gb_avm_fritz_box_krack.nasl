###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_krack.nasl 7857 2017-11-22 07:24:15Z cfischer $
#
# Multiple AVM FRITZ!Box WPA2 Key Reinstallation Vulnerabilities - KRACK
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:avm:fritzbox';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108292");
  script_version("$Revision: 7857 $");
  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080",
                "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13084", "CVE-2017-13086",
                "CVE-2017-13087", "CVE-2017-13088");
  script_bugtraq_id(101274);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 08:24:15 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-22 07:59:41 +0100 (Wed, 22 Nov 2017)");
  script_name("Multiple AVM FRITZ!Box WPA2 Key Reinstallation Vulnerabilities - KRACK");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://avm.de/service/aktuelle-sicherheitshinweise/");
  script_xref(name:"URL", value:"https://en.avm.de/service/current-security-notifications/");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"solution", value:"Update the firmware to version 6.92 or later.");

  script_tag(name:"summary", value:"WPA2 as used in several models of the AVM FRITZ!Box are prone to
  multiple security weaknesses aka Key Reinstallation Attacks (KRACK).");

  script_tag(name:"affected", value:"AVM FRITZ!Box 7590, 7580, 7560 and 7490 with a firmware below 6.92,
  if configured to access the internet provided by another router via wireless LAN uplink.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

get_app_version( cpe:CPE, nofork:TRUE ); # To have a reference to the Detection NVT.

if( ! model = get_kb_item( "avm/fritz/model" ) ) exit( 0 );
if( ! fw_version = get_kb_item( "avm/fritz/firmware_version" ) ) exit( 0 );

valid_models = make_list( "7590", "7580", "7560", "7490" ); # Those got a fix from AVM but other models might be vulnerable as well

foreach m( valid_models ) {
  if( egrep( string:model, pattern:'^' + m ) ) {
    vuln_model = TRUE;
    break;
  }
}

if( ! vuln_model ) exit( 0 );

fw = split( fw_version, sep:'.', keep:TRUE );
if( max_index( fw ) < 3 ) exit( 0 );

fw_version = fw[1] + fw[2];
patch = "06.92";

if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
