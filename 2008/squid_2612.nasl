###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_2612.nasl 4907 2017-01-02 13:16:52Z cfi $
#
# Squid < 2.6.STABLE12 Denial-of-Service Vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2007 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = 'cpe:/a:squid-cache:squid';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80017");
  script_version("$Revision: 4907 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 14:16:52 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(80017);
  script_cve_id("CVE-2007-1560");
  script_name("Squid < 2.6.STABLE12 Denial-of-Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2007 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2007_1.txt");

  tag_summary = "A vulnerability in TRACE request processing has been reported in Squid,
  which can be exploited by malicious people to cause a denial of service.";

  tag_solution = "Upgrade to squid 2.6 or newer.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

data = get_kb_item( "www/" + port + "/Squid" );
if( ! data ) exit( 0 );

# checking for the Version < =2.6
if( egrep( pattern:"2\.([0-5]\.|6\.STABLE([0-9][^0-9]|1[01][^0-9]))", string:data ) ) {
  report = report_fixed_ver( installed_version:data, fixed_version:"2.6" );
  security_message( port:port, data:report );
  exit( 0 );      
}

exit( 99 );