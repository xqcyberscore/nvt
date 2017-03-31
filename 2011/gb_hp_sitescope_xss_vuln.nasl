###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sitescope_xss_vuln.nasl 3569 2016-06-21 07:43:44Z benallard $
#
# HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker-supplied HTML and script code to
  run in the context of the affected browser, potentially allowing the attacker
  to steal cookie-based authentication credentials or to control how the site
  is rendered to the user. Other attacks are also possible.
  Impact Level: Application";
tag_affected = "HP SiteScope versions 9.54, 10.13, 11.01, and 11.1";
tag_insight = "The flaws are caused by input validation errors when processing user-supplied
  data, which could allow cross site scripting or HTML injection attacks.";
tag_solution = "Upgrade to HP SiteScope version 11.1 and apply the SS1110110412 hotfix
  http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02807712";
tag_summary = "This host is running HP SiteScope and is prone to cross site
  scripting and HTML injection vulnerabilities.";

if(description)
{
  script_id(801881);
  script_version("$Revision: 3569 $");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:43:44 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-1726", "CVE-2011-1727");
  script_bugtraq_id(47554);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP SiteScope Cross Site Scripting and HTML Injection Vulnerabilities");
  script_xref(name : "URL" , value : "https://secunia.com/advisories/44354");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45958");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1091");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02807712");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if SiteScope is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!get_port_state(port)) {
  exit(0);
}

## Send and Receive the response
sndReq = http_get(item:string("/SiteScope/index.html"), port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm SiteScope
if("<TITLE>Login - SiteScope</TITLE>" >< rcvRes)
{
  ## Construct attack request
  url = string("/SiteScope/jsp/hosted/HostedSiteScopeMessage.jsp?messageKey=",
                "<script>alert('openvas-xss-test')</script>");

  ## Try XSS and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"en.<script>alert\('openvas-xss-test'\)</script>"))
  {
    security_message(port);
    exit(0);
  }
}
