###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_1200_66349.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Siemens SIMATIC S7-1200  Denial of Service Vulnerability
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

CPE = "cpe:/a:siemens:simatic_s7_1200";

tag_insight = "Siemens SIMATIC S7-1200 CPU PLC devices with firmware before 4.0 allow
remote attackers to cause a denial of service (defect-mode transition) via crafted HTTP
packets, crafted ISO-TSAP packets or crafted HTTPS packets.";

tag_impact = "Remote attackers may exploit this issue to cause denial-of-service
conditions, denying service to legitimate users.";

tag_affected = "Versions prior to SIMATIC S7-1200 4.0 are vulnerable.";

tag_summary = "Siemens SIMATIC S7-1200 is prone to a denial-of-service vulnerability.";
tag_solution = "Updates are available.";
tag_vuldetect = "Check the firmware version";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103930");
 script_bugtraq_id(66349,66344,66353);
 script_cve_id("CVE-2014-2254","CVE-2014-2256","CVE-2014-2258");
 script_version ("$Revision: 6759 $");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_name("Siemens SIMATIC S7-1200  Denial of Service Vulnerability");

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66349");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66353");
 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66344");
 script_xref(name:"URL", value:"http://subscriber.communications.siemens.com/");

 script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
 script_tag(name:"creation_date", value:"2014-03-31 13:32:29 +0200 (Mon, 31 Mar 2014)");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_simatic_s7_version.nasl");
 script_mandatory_keys("simatic_s7/detected");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 script_tag(name:"qod_type", value:"remote_banner");
 script_tag(name: "solution_type", value: "VendorFix");

 exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version =~ "^(2\.|3\.)" )
{
  security_message( port:port );
  exit( 0 );
}

exit( 0 );
