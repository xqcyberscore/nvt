##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_print_server_authe_bypass_vuln.nasl 4622 2016-11-25 06:51:16Z cfi $
#
# TRENDnet Print Server Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to reset
print server to factory settings or changing its IP address without password
security check and obtain the sensitive information.

Impact Level: Application";

tag_affected = "TRENDnet TE100-P1U Print Server Firmware 4.11";

tag_insight = "The flaw is due to a failure of the application to validate
authentication credentials when processing print server configuration
change requests.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running TRENDnet Print Server and is prone to
authentication bypass vulnerability.";

if(description)
{
  script_id(803720);
  script_version("$Revision: 4622 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 07:51:16 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2013-06-25 12:51:19 +0530 (Tue, 25 Jun 2013)");
  script_name("TRENDnet Print Server Authentication Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26401");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/trendnet-te100-p1u-authentication-bypass");
  script_summary("Try to read the restricted file Network.htm");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application
if(http_vuln_check(port:port, url:"/StsSys.htm", pattern:">TRENDNET",
   extra_check:">Printer"))
{
  ## Confirm the exploit by reading content of Network.htm
  if(http_vuln_check(port:port, url:"/Network.htm", pattern:">TRENDNET",
     extra_check:make_list("IP Address<", "DNS Server Address<")))
  {
    security_message(port:port);
    exit(0);
  }
}
