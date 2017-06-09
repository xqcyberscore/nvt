###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_rational_clearquest_mult_info_disc_vuln.nasl 6093 2017-05-10 09:03:18Z teissa $
#
# IBM Rational ClearQuest Multiple Information Disclosure Vulnerabilities
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

tag_impact = "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.
  Impact Level: Application";

tag_affected = "IBM Rational ClearQuest 7.1.x to 7.1.2.7 and 8.x to 8.0.0.3";
tag_insight = "The flaws are due to improper access controls on certain post-installation
  sample scripts. By sending a direct request, an attacker could obtain system
  paths, product versions, and other sensitive information.";
tag_solution = "Apply the patch from below link,
  http://www-01.ibm.com/support/docview.wss?uid=swg21606317";
tag_summary = "This host is installed with IBM Rational ClearQuest and is prone to
  multiple information disclosure vulnerabilities.";

if(description)
{
  script_id(803709);
  script_version("$Revision: 6093 $");
  script_bugtraq_id(54222);
  script_cve_id("CVE-2012-0744");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-06-03 17:40:28 +0530 (Mon, 03 Jun 2013)");
  script_name("IBM Rational ClearQuest Multiple Information Disclosure Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74671");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21606317");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21599361");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Request for the search.cgi
sndReq = http_get(item:"/cqweb/login", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

## Confirm the Application
if(">Rational<" >< rcvRes && "Welcome to Rational ClearQuest Web" >< rcvRes)
{

  ## Try to access post-installation sample scripts
  sndReq = http_get(item:"/cqweb/j_security_check", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ##  check the patch based response
  if((rcvRes =~ "HTTP/1.. 200 OK") && (rcvRes !~ "HTTP/1.. 404")
     && (">Object not found!<" >!< rcvRes))
  {
    security_message(port);
    exit(0);
  }
}
