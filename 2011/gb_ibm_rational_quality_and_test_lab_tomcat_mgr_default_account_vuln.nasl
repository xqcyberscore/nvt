##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_rational_quality_and_test_lab_tomcat_mgr_default_account_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM Rational Quality Manager and Rational Test Lab Manager Tomcat Default Account Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of an affected application.
  Impact Level: Application.";
tag_affected = "Versions prior  to IBM Rational Quality Manager and IBM Test Lab
  Manager 7.9.0.3 build:1046";
tag_insight = "The flaw exists within the installation of the bundled Tomcat server.
  The default ADMIN account is improperly disabled within 'tomcat-users.xml'
  with default password. A remote attacker can use this vulnerability to
  execute arbitrary code under the context of the Tomcat server.";
tag_solution = "Upgrade to version 7.9.0.3 build 1046 or higher
  For updates refer to https://www.ibm.com/developerworks/rational/products/testmanager";
tag_summary = "The host is running Tomcat server in IBM Rational Quality Manager/
  IBM Rational Test Lab Manager has a default password for the ADMIN account.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800193");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2010-4094");
  script_bugtraq_id(44172);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("IBM Rational Quality Manager and Rational Test Lab Manager Tomcat Default Account Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41784");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-214");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Oct/1024601.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_family("Web Servers");
  script_require_ports("Services/www", 80, 9080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:9080);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Construct Crafted GET request
req = string ( "GET /manager/html HTTP/1.1\r\n", "Host: ", host, "\r\n",
                "Authorization: Basic QURNSU46QURNSU4=\r\n",
                "\r\n"
             );
res = http_keepalive_send_recv(port:port, data:req);

## Check the response
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 OK", string:res) && "IBM Corporation"
   >< res &&  ( "deployConfig" >< res || "installConfig" >< res ) &&
   ("deployWar" >< res || "installWar" >< res))
{
  security_message(port);
}

