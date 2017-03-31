###############################################################################
# OpenVAS Vulnerability Test
# $Id: nsd_35029.nasl 4449 2016-11-09 07:50:19Z cfi $
#
# NSD (Name Server Daemon) 'packet.c' Off-By-One Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:nlnetlabs:nsd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100209");
  script_version("$Revision: 4449 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-09 08:50:19 +0100 (Wed, 09 Nov 2016) $");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(35029);
  script_name("NSD (Name Server Daemon) 'packet.c' Off-By-One Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("nsd_version.nasl");
  script_mandatory_keys("nsd/installed");

  tag_summary = "NSD is prone to an off-by-one buffer-overflow vulnerability
  because the server fails to perform adequate boundary checks on
  user-supplied data.";

  tag_impact = "Successfully exploiting this issue will allow attackers to
  execute arbitrary code within the context of the affected server.
  Failed exploit attempts will result in a denial-of-service condition.";

  tag_affected = "Versions prior to NSD 3.2.2 are vulnerable.";

  tag_solution = "The vendor has released fixes. Please see http://www.nlnetlabs.nl/projects/nsd/
  for more information.";

  tag_vuldetect = "Check the version.";

  script_tag(name:"vuldetect", value:tag_vuldetect);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"3.2.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.2" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
