##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_event_horizon_xss_n_sql_inj_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Event Horizon 'modfile.php' Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "Event Horizon version 1.1.10 and prior.";

tag_insight = "The flaw exists due to the improper validation of user supplied data to
  'YourEmail' and 'VerificationNumber' parameters to 'modfile.php' script.";
tag_solution = "Upgrade to the Event Horizon version 1.1.11
  http://code.google.com/p/eventh/downloads/list";
tag_summary = "This host is running Event Horizon and is prone cross site
  scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(902088);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(41580);
  script_cve_id("CVE-2010-2854", "CVE-2010-2855");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Event Horizon 'modfile.php' Cross Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40517");
  script_xref(name : "URL" , value : "http://freshmeat.net/projects/eventh/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_event_horizon_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

eventhPort = get_http_port(default:80);
if(!get_port_state(eventhPort)){
  exit(0);
}

## Get Event Horizon path from KB
if(!dir = get_dir_from_kb(port:eventhPort, app:"Event/Horizon/Ver")){
 exit(0);
}

## Try expliot and check response
sndReq = http_get(item:string(dir, '/modfile.php?YourEmail=<script>alert' +
                  '("OpenVAS-XSS-Testing")</script>'), port:eventhPort);
rcvRes = http_send_recv(port:eventhPort, data:sndReq);

## Check the Response string
if(rcvRes =~ "HTTP/1\.. 200" && '<script>alert("OpenVAS-XSS-Testing")</script>' >< rcvRes){
    security_message(eventhPort);
}
