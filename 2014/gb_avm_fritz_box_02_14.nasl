###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_02_14.nasl 5072 2017-01-24 10:16:40Z cfi $
#
# Multiple AVM FRITZ!Box Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103911");
  script_version("$Revision: 5072 $");
  script_bugtraq_id(74927, 65520);
  script_cve_id("CVE-2014-9727");
  script_name("Multiple AVM FRITZ!Box Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 11:16:40 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2014-02-19 15:07:20 +0100 (Wed, 19 Feb 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"http://www.avm.de/de/Sicherheit/liste_update.html");
  script_xref(name:"URL", value:"http://www.fritzbox.eu/en/news/2014/security_updates_available.php");
  script_xref(name:"URL", value:"http://www.heise.de/newsticker/meldung/Jetzt-Fritzbox-aktualisieren-Hack-gegen-AVM-Router-auch-ohne-Fernzugang-2115745.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65520");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references section
  for more information.");

  script_tag(name:"summary", value:"AVM FRITZ!Box is prone to multiple vulnerabilities");

  script_tag(name:"affected", value:"See the list at http://www.avm.de/de/Sicherheit/liste_update.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

get_app_version( cpe:CPE, nofork:TRUE ); # To have a reference to the Detection NVT.

if( ! model = get_kb_item( "avm/fritz/model" ) ) exit( 0 );
if( ! fw_version = get_kb_item( "avm/fritz/firmware_version" ) ) exit( 0 );

fixes = make_array(
                   "7570", "04.92",
                   "7490", "06.03",
                   "7390", "06.03",
                   "7362 SL", "06.03",
                   "7360 SL", "06.03",
                   "7360", "06.03",
                   "7330 SL", "06.03",
                   "7330", "06.03",
                   "7320", "06.03",
                   "7312", "06.03",
                   "7272", "06.03",
                   "7270 v2", "05.54",
                   "7270 v3", "05.54",
                   "7270 v1","04.89",
                   "7240", "05.54",
                   "7170 SL", "04.81",
                   "7170", "04.88",
                   "7150", "04.72",
                   "7141", "04.77",
                   "7112", "04.88",
                   "6842 LTE", "06.03",
                   "6840 LTE", "06.03",
                   "6810 LTE", "06.03",
                   "6360 Cable", "06.03",
                   "6340 Cable", "06.03",
                   "6320 Cable", "06.03",
                   "3390", "06.03",
                   "3370", "06.03",
                   "3272", "06.03",
                   "3270", "05.54"
                   );

if( ! fixes[model] ) exit( 99 );
patch = fixes[model];

fw = split( fw_version, sep:'.', keep:TRUE);

if( max_index( fw ) < 3 ) exit( 0 );

fw_version = fw[1] + fw[2];

if( version_is_less( version:fw_version, test_version:patch ) )
{
  report = 'Model: ' + model + '\nInstalled Firmware: ' + fw_version + '\nFixed Firmware:     ' + patch + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
