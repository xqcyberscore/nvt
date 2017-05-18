# OpenVAS Vulnerability Test
# $Id: remote-detect-Opentaps_ERP_CRM.nasl 5888 2017-04-07 09:01:53Z teissa $
# Description: This script ensure that the Opentaps ERP + CRM is installed and running
#
# remote-detect-Opentaps_ERP_CRM.nasl
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

tag_summary = "The remote host is running Opentaps ERP + CRM. 
opentaps is a full-featured ERP + CRM suite which incorporates several open source projects, 
including Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework; 
Pentaho and JasperReports for business intelligence; Funambol for mobile device and Outlook integration; 
and the opentaps applications which provide user-driven applications for CRM, accounting and finance, 
warehouse and manufacturing, and purchasing and supply chain mmanagement.";

tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks,
or disable the service if not used.";



if(description)
{
script_id(101021);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5888 $");
script_tag(name:"last_modification", value:"$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
script_tag(name:"creation_date", value:"2009-04-23 00:18:39 +0200 (Thu, 23 Apr 2009)");
script_tag(name:"cvss_base", value:"0.0");
name = "Opentaps ERP + CRM service detection";
script_name(name);
 

summary = "Detect a running Opentaps Open Source ERP + CRM";

script_category(ACT_GATHER_INFO);
script_tag(name:"qod_type", value:"remote_banner");

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
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


thePort = get_http_port(default:8080);

pages = make_array(0,'/',1,'webtools/control/main');
report = '';

softwareRequest = string("GET ", pages[0], " HTTP/1.1\r\n","Host: ", get_host_name(), "\r\n\r\n");
versionRequest = string("GET /", pages[1], " HTTP/1.1\r\n","Host: ", get_host_name(), "\r\n\r\n");

softwareReply = http_send_recv(port:thePort, data:softwareRequest);
versionReply = http_send_recv(port:thePort, data:versionRequest);

if(versionReply =~ "^HTTP/1.[0-1]+ 404")exit(0);

if(softwareReply){

	servletContainer = eregmatch(pattern:"Server: Apache-Coyote/([0-9.]+)",string:softwareReply, icase:TRUE);
	opentapsTitlePattern = eregmatch(pattern:"<title>([a-zA-Z +]+)</title>",string:softwareReply, icase:TRUE);

	if(opentapsTitlePattern){
		if('opentaps' >< opentapsTitlePattern[0]){
			report += " The remote host is running " + opentapsTitlePattern[1];
			replace_kb_item(name:"OpentapsERP/installed", value:TRUE);
			replace_kb_item(name:"OpentapsERP/port", value:thePort);
		} else {
                  exit(0);
		}  
	} else {
          exit(0);
	}  

	if((servletContainer)){
		replace_kb_item(name:"ApacheCoyote/installed", value:TRUE);
		replace_kb_item(name:"ApacheCoyote/version", value:servletContainer[1]);
		report += " on " + servletContainer[0];
	}
			
}

if(versionReply){

	version = eregmatch(pattern:'<p><a href="http://www.opentaps.org" class="tabletext">([a-zA-Z +]+)</a> ([0-9.]+).<br/>',string:versionReply, icase:TRUE);
	servletContainer = eregmatch(pattern:"Server: Apache-Coyote/([0-9.]+)",string:versionReply, icase:TRUE);

	if(version){
		report += " Detected " + version[1] + " " + version[2];
		replace_kb_item(name:"OpentapsERP/installed", value:TRUE);
		replace_kb_item(name:"OpentapsERP/version", value:version[2]);
		replace_kb_item(name:"OpentapsERP/port", value:thePort);
	} else {
          exit(0);
	}  

	if((servletContainer)){
		replace_kb_item(name:"ApacheCoyote/installed", value:TRUE);
		replace_kb_item(name:"ApacheCoyote/version", value:servletContainer[1]);
		report += " on " + servletContainer[0];
	}
}

if(report)
	log_message(port:thePort, data:report);
