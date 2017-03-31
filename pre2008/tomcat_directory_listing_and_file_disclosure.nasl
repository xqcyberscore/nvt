###############################################################################
# OpenVAS Vulnerability Test
# $Id: tomcat_directory_listing_and_file_disclosure.nasl 4355 2016-10-26 13:50:18Z cfi $
#
# Apache Tomcat Directory Listing and File disclosure
#
# Authors:
# Bekrar Chaouki - A.D.Consulting <bekrar@adconsulting.fr>
#
# Copyright:
# Copyright (C) 2003 A.D.Consulting
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11438");
  script_version("$Revision: 4355 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-26 15:50:18 +0200 (Wed, 26 Oct 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(6721);
  script_cve_id("CVE-2003-0042");
  script_name("Apache Tomcat Directory Listing and File disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 A.D.Consulting");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheTomcat/installed");

  tag_summary = "Apache Tomcat (prior to 3.3.1a) is prone to a directory listing and file 
  disclosure vulnerability, it allows remote attackers to potentially list 
  directories even with an index.html or other file present, or obtain 
  unprocessed source code for a JSP file.";

  tag_solution = "Upgrade to Tomcat 4.1.18 or newer version.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

res = http_get_cache( item:"/", port:port );
if( isnull( res ) ) exit( 0 );

if( ( "Index of /" >< res ) || ( "Directory Listing" >< res ) ) exit( 0 );

req = http_get( item:"/<REPLACEME>.jsp", port:port );
req = str_replace( string:req, find:"<REPLACEME>", replace:raw_string( 0 ) );
res = http_keepalive_send_recv( port:port, data:req );

if( isnull( res ) ) exit( 0 );

if( ( "Index of /" >< res ) || ( "Directory Listing" >< res ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );