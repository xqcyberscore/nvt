###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_universal_cmdb_http_trace_info_disc_vuln.nasl 7497 2017-10-19 07:06:06Z santu $
#
# HPE Universal CMDB 'HTTP TRACE' Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:universal_cmbd_foundation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811868");
  script_version("$Revision: 7497 $");
  script_cve_id("CVE-2014-7883");
  script_bugtraq_id(72432);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-19 09:06:06 +0200 (Thu, 19 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-16 13:04:54 +0530 (Mon, 16 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("HPE Universal CMDB 'HTTP TRACE' Information Disclosure Vulnerability");

  script_tag(name:"summary" , value:"The host is installed with HP Universal 
  CMDB and is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a 'HTTP TRACE' request and checks the 
  response.");

  script_tag(name:"insight" , value:"The flaw is due to enabling the HTTP TRACE 
  method.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote 
  attackers to send a specially crafted HTTP TRACE request to obtain potentially 
  sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"HPE Universal CMDB Probe 9.05, 10.01, and 
  10.11");

  script_tag(name:"solution", value:"The vendor has described a configuration 
  recommendation to fix the vulnerability as given in link
  http://www.kb.cert.org/vuls/id/867593");

  script_tag(name:"solution_type", value:"Mitigation");

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/867593");
  script_xref(name : "URL" , value : "https://securitytracker.com/id/1031688");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hpe_universal_cmdb_detect.nasl");
  script_mandatory_keys("HP/UCMDB/Installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


##
### Code Starts Here
##

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");


## Variable Initialization
ucmdbPort = "";
req = "";
res = "";

## Get HTTP Port
if(!ucmdbPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get host
host = http_host_name(port:ucmdbPort);
if(!host){
  exit(0);
}

## url
url = "/status/";

## Send request and receive response
req = string("TRACE ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

res = http_keepalive_send_recv(port:ucmdbPort, data:req);

## Confirm exploit
## Checking http trace request is successful or not
## The message body contains the request message as received by the server.
## Content-Type is 'message/http' as expected for trace request
if (res =~ "HTTP/1.. 200 OK" && egrep(pattern:"Content-Type: message/http", string:res) &&
    "TRACE /status/ HTTP/1.1" >< res)
{
  report = report_vuln_url(port: ucmdbPort, url: url);
  security_message(port: ucmdbPort, data: report);
  exit(0);
}

exit(0);
