##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_xwork_info_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Apache Struts2 'XWork' Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:apache:struts";
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801940");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-2088");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Struts2 'XWork' Information Disclosure Vulnerability");

  script_tag(name: "summary" , value:"This host is running Apache Struts and is
  prone to information disclosure vulnerability.");

  script_tag(name: "vuldetect" , value:"Send a crafted SNMP request and
  check whether it is able read the sensitive information");

  script_tag(name: "insight" , value:"The flaw is due to error in XWork, when handling
  the 's:submit' element and a nonexistent method, which gives sensitive information
  about internal Java class paths.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers to obtain potentially sensitive
  information about internal Java class paths via vectors involving an s:submit
  element and a nonexistent method,

  Impact Level: Application.");

  script_tag(name: "affected" , value:"XWork version 2.2.1 in Apache Struts 2.2.1");

  script_tag(name: "solution" , value:"Upgrade to Struts version 2.2.3 or later
  For updates refer to http://struts.apache.org/download.cgi");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/WW-3579");
  script_xref(name : "URL" , value : "http://www.ventuneac.net/security-advisories/MVSA-11-006");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get HTTP Port
if(!port = get_app_port(cpe:CPE)){
 exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:port))
{
  exit(0);
}

## Send and Receive the response
req = http_get(item:string(dir,"/example/HelloWorld.action"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the application
if("<title>Struts" >< res)
{
  ## Construct the request to get no existing methods
  req = http_get(item:string(dir,"/Nonmethod.action"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ##  Confirm the exploit
  if("Stacktraces" >< res &&  "Nonmethod" >< res)
  {
    security_message(port);
    exit(0);
  }
}
