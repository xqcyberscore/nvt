###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_allegro_rompager_cve_2014_9222.nasl 9982 2018-05-28 12:00:03Z cfischer $
#
# Allegro RomPager `Misfortune Cookie` Vulnerability
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

CPE = "cpe:/a:allegrosoft:rompager";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105154");
 script_cve_id("CVE-2014-9222");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 9982 $");

 script_name("Allegro RomPager `Misfortune Cookie` Vulnerability");

 script_xref(name:"URL", value:"http://mis.fortunecook.ie/");
 script_xref(name:"URL", value:"http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf");

 script_tag(name: "vuldetect" , value:"Send a HTTP GET request with a special crafted cookie and check the response");
 script_tag(name: "solution" , value:"Ask the vendor for an update");

 script_tag(name: "summary" , value:"The remote Allegro RomPager service is vulnerable to the `Misfortune Cookie` Vulnerability");

 script_tag(name: "affected" , value:"RomPager services with versions before 4.34");

 script_tag(name:"last_modification", value:"$Date: 2018-05-28 14:00:03 +0200 (Mon, 28 May 2018) $");
 script_tag(name:"creation_date", value:"2014-12-23 10:22:44 +0100 (Tue, 23 Dec 2014)");
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_allegro_rompager_detect.nasl");
 script_require_ports("Services/www", 7547);
 script_mandatory_keys("allegro_rompager/installed");

 script_tag(name:"solution_type", value:"NoneAvailable");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

url = '/tr069';
rand = '/OpenVAS_' + rand();
cookie = 'C107373883=' + rand;

if( http_vuln_check( port:port, url:url, pattern:rand, extra_check:'was not found on the RomPager', cookie:cookie ) )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
