###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_management_console_detect.nasl 5877 2017-04-06 09:01:48Z teissa $
#
# SAP Management Console Detection
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103829");
 script_version ("$Revision: 5877 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-06 11:01:48 +0200 (Thu, 06 Apr 2017) $");
 script_tag(name:"creation_date", value:"2013-11-13 12:08:59 +0100 (Wed, 13 Nov 2013)");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("SAP Management Console Detection");

 script_tag(name : "summary" , value : "The script sends a connection request to the server and attempts to
 extract the version number from the reply.");

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 50013);

 script_tag(name:"qod_type", value:"remote_banner");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:50013);
if(!get_port_state(port))exit(0);

url = '/sapmc/sapmc.html';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("SAP Management Console" >!< buf && "com.sap.managementconsole.applet" >!< buf)exit(0);

host = get_host_name();
if( port != 80 && port != 443 )
  host += ':' + port;

soap = '<?xml version="1.0" encoding="utf-8"?>\r\n' +
'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">\r\n' +
'<SOAP-ENV:Header>\r\n' + 
'<sapsess:Session xlmns:sapsess="http://www.sap.com/webas/630/soap/features/session/">\r\n' + 
'<enableSession>true</enableSession>\r\n' + 
'</sapsess:Session>\r\n' + 
'</SOAP-ENV:Header>\r\n' +
'<SOAP-ENV:Body>\r\n' +
'<ns1:GetVersionInfo xmlns:ns1="urn:SAPControl"></ns1:GetVersionInfo>\r\n' +
'</SOAP-ENV:Body>\r\n' +
'</SOAP-ENV:Envelope>\r\n\r\n';

len = strlen(soap);

req = 'POST / HTTP/1.1' + 
      'Host: ' + host + '\r\n' + 
      'Content-Length: ' + len + '\r\n' +
      'SOAPAction: ""\r\n' + 
      'Content-Type: text/xml; charset=UTF-8\r\n' +
      '\r\n' + 
      soap;

result = http_send_recv(port:port, data:req, bodyonly:FALSE);
if(result !~ "HTTP/1.. 200" || "GetVersionInfoResponse" >!< result || "VersionInfo" >!< result)exit(0);

version = eregmatch(pattern:"<VersionInfo>([^<]+)</VersionInfo>", string:result);

if(!isnull(version[1])) {
  set_kb_item(name:'www/' + port + '/sap_management_console/version', value:version[1]);
  set_kb_item(name:"sap_management_console/installed", value:TRUE);
}

cpe = 'cpe:/a:sap:netweaver';
register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

log_message(data: 'Detected SAP Management Console.\nCPE: ' + cpe + '\nConcluded: ' + version[0] + '\n', port:port);
exit(0);
