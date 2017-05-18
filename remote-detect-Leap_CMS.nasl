# OpenVAS Vulnerability Test
# $Id: remote-detect-Leap_CMS.nasl 5877 2017-04-06 09:01:48Z teissa $
# Description: This script ensure that the Leap CMS is installed and running
#
# remote-detect-Leap_CMS.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
#

tag_summary = "The remote host is running the Leap CMS. 
Leap is a single file, template independent, PHP and MySQL Content Management System.";

tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks,
or disable the service if not used.";



if(description)
{
script_id(101025);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5877 $");
script_tag(name:"last_modification", value:"$Date: 2017-04-06 11:01:48 +0200 (Thu, 06 Apr 2017) $");
script_tag(name:"creation_date", value:"2009-04-30 23:11:17 +0200 (Thu, 30 Apr 2009)");
script_tag(name:"cvss_base", value:"0.0");
name = "Leap CMS service detection";
script_name(name);
 
summary = "Detect a running Leap CMS";

script_category(ACT_GATHER_INFO);
script_tag(name:"qod_type", value:"remote_banner");

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_dependencies("find_service.nasl");
script_require_ports("Services/www", 80, 8080);


script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
exit(0);

}

#
# The script code starts here
#

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.101025";
SCRIPT_DESC = "Leap CMS service detection";

port = get_http_port(default:80);
report = '';

request = string("GET /leap/", " HTTP/1.1\r\n","Host: ", get_host_name(), "\r\n\r\n");

response = http_send_recv(port:port, data:request);


if(response){

	vendor = eregmatch(pattern:'Powered by <a href="http://leap.gowondesigns.com/">Leap</a> ([0-9.]+)',string:response, icase:TRUE);
	
	if(vendor){
		
		report += "\n Detected Leap CMS Version: " + vendor[1];
		set_kb_item(name:"LeapCMS/installed", value:TRUE);
		set_kb_item(name:"LeapCMS/port", value:port);
		set_kb_item(name:"LeapCMS/version", value:vendor[1]);
     
                ## build cpe and store it as host_detail
                cpe = build_cpe(value:vendor[1], exp:"^([0-9.]+)", base:"cpe:/a:gowondesigns:leap:");
                if(!isnull(cpe))
                   register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

		server = eregmatch(pattern:"Server: ([a-zA-Z]+)/([0-9.]+)",string:response);

	        if(server){
		
	  	        set_kb_item(name:"LeapServer/type", value:server[1]);
		        set_kb_item(name:"LeapServer/version", value:server[2]);
		        report += " on " + server[0];
		        }
	}
}
if(report)
	log_message(port:port, data:report);
