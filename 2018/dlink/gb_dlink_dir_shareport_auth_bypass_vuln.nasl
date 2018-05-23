###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_shareport_auth_bypass_vuln.nasl 9917 2018-05-22 08:38:12Z ckuersteiner $
#
# D-Link DIR Routers SharePort Authentication Bypass Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113146");
  script_version("$Revision: 9917 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-22 10:38:12 +0200 (Tue, 22 May 2018) $");
  script_tag(name:"creation_date", value:"2018-03-29 09:53:55 +0200 (Thu, 29 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-9032");

  script_name("D-Link DIR Routers SharePort Authentication Bypass Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_detect.nasl");
  script_require_ports("Services/www", 80, 8080, 8181);
  script_mandatory_keys("host_is_dlink_dir");

  script_tag(name:"summary", value:"D-Link DIR Routers are prone to Authentication Bypass Vulnerability.");
  script_tag(name:"vuldetect", value:"The script tries to access protected information without authentication.");
  script_tag(name:"insight", value:"The directories '/category_view.php' and '/folder_view.php' can be accessed directly without authentication.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access information about the target system
  that would normally require authentication.");
  script_tag(name:"affected", value:"D-Link DIR Routers with SharePort functionality. Firmware versions through 2.06.");
  script_tag(name:"solution", value:"No known solution is available as of 22nd May, 2018. Information regarding
this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.youtube.com/watch?v=Wmm4p8znS3s");

  exit( 0 );
}

CPE = 'cpe:/o:d-link';

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

# D-Link NVTs normally use 8080, but Shodan has more than ten times the results with 8181
if( ! port = get_app_port_from_cpe_prefix( cpe: CPE ) ) exit( 0 );

vuln_urls = make_list( '/folder_view.php', '/category_view.php' );

foreach url ( vuln_urls ) {

  req = http_get( port: port, item: url );
  res = http_keepalive_send_recv( port: port, data: req );

  if( res =~ 'HTTP/1.. 200' && res =~ '<title>SharePort Web Access</title>' && res =~ 'href="webfile_css/layout.css"' ) {
    report = report_vuln_url( port: port, url: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
