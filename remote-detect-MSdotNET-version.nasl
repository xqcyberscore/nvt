# OpenVAS Vulnerability Test
# $Id: remote-detect-MSdotNET-version.nasl 2837 2016-03-11 09:19:51Z benallard $
# Description: detects the version of Microsoft .Net Framework
#
# remote-detect-MSdotNET-version.nasl
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

tag_summary = "The remote host seems to have Microsoft .NET installed.";

tag_solution = "It's recommended to disable verbose error displaying to avoid version detection.
this can be done througth the IIS management console.";



if(description)
{
script_id(101007);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
script_tag(name:"creation_date", value:"2009-03-15 21:21:09 +0100 (Sun, 15 Mar 2009)");
script_tag(name:"cvss_base", value:"0.0");
name = "Microsoft dotNET version grabber";
script_name(name);
 
summary = "The remote host seems to have Microsoft .NET installed";

script_summary(summary);

script_category(ACT_GATHER_INFO);
script_tag(name:"qod_type", value:"remote_banner");

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "General";
script_family(family);
script_dependencies("find_service.nasl");
script_require_ports("Services/www");



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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.101007";
SCRIPT_DESC = "Microsoft dotNET version grabber";


# request a non existent random page
page = string(rand() + ".aspx");

port = get_http_port(default:80);
	
request = string(
    "GET /", page, " HTTP/1.0\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; OpenVAS)\r\n",
    "Accept-Language: en-us,en;q=0.5\r\n",
    "Keep-Alive: 300\r\n",
    "Connection: keep-alive\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    );


	
	# Get back the response
	response = http_keepalive_send_recv(port:port, data:request, bodyonly:1);

	# Get the ASP.NET Microsoft .Net Framework version
	# a response example:
	# Version Information: Microsoft .NET Framework Version:2.0.50727.1433; ASP.NET Version:2.0.50727.1433
	dotNet_header = eregmatch(pattern:"Microsoft .NET Framework Version:([0-9.]+)",string:response, icase:TRUE);
	aspNet_header = eregmatch(pattern:"ASP.NET Version:([0-9.]+)",string:response, icase:TRUE);

	if(('Version Information' >< response) && dotNet_header){
		report = "OpenVAS was able to Detected " + dotNet_header[0];

		# save informations into the kb
		set_kb_item(name:"dotNET/install", value:TRUE);
		set_kb_item(name:"dotNET/port", value:port);
		set_kb_item(name:"dotNET/version", value:dotNet_header[1]);
	   
                ## build cpe and store it as host_detail
                cpe = build_cpe(value:dotNet_header[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:.net_framework:");
                if(!isnull(cpe))
                   register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
		
		if(aspNET_header >< response){
			report +=  " and " + aspNet_header[0];
	
			# save informations into the kb
			set_kb_item(name:"aspNET/installed", value:TRUE);
			set_kb_item(name:"aspNET/version", value:aspNet_header[1]);
		}
	

		# report all gathered informations
		log_message(port:port, data:report);
	}
