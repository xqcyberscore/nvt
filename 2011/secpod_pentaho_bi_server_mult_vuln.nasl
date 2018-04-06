###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pentaho_bi_server_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Pentaho BI Server Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site or obtain sensitive information.
  Impact Level: Application";
tag_affected = "Pentaho BI Server version 1.7.0.1062 and prior.";
tag_insight = "- Input passed via the 'outputType' parameter to ViewAction is not properly
    sanitised before being returned to the user. This can be exploited to
    execute arbitrary HTML and script code in a user's browser session in
    context of an affected site.
  - Password field with autocomplete enabled, which might allow physically
    proximate attackers to obtain the password.
  - Disclosure of session ID (JSESSIONID) in URL, which allows attackers to
    obtain it from session history, referer headers, or sniffing of web traffic.";
tag_solution = "Upgrade to Pentaho BI Server 3.5.0 GA or later,
  For updates refer to http://www.pentaho.com/download/";
tag_summary = "The host is running Pentaho BI Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902568");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2009-5099", "CVE-2009-5100", "CVE-2009-5101");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Pentaho BI Server Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37024");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507168/100/0/threaded");
  script_xref(name : "URL" , value : "http://antisnatchor.com/2009/06/20/pentaho-1701062-multiple-vulnerabilities/");
  script_xref(name : "URL" , value : "http://jira.pentaho.com/browse/BISERVER-2698?page=com.atlassian.jira.plugin.system.issuetabpanels:all-tabpanel");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Send and Receive the response
req = http_get(item:string("/pentaho/Login"),  port:port);
res = http_send_recv(port:port, data:req);

## Confirm the application
if("Pentaho BI Platform" >< res)
{
  ## Check for the Password field with autocomplete enabled
  if('<td colspan="2"><input type=\'password\' name=\'j_password\' '+
                                          'size="30" ></td>' >< res)
  {
    security_message(port);
    exit(0);
  }
}
