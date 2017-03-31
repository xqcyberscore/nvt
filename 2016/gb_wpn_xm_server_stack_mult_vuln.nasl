###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wpn_xm_server_stack_mult_vuln.nasl 5265 2017-02-10 15:05:48Z teissa $
#
# WPN-XM Server Stack Multiple Vulnerabilities
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:wpnxm_server_stack:wpnxm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807912");
  script_version("$Revision: 5265 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-10 16:05:48 +0100 (Fri, 10 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-04-19 15:22:01 +0530 (Tue, 19 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("WPN-XM Server Stack Multiple Vulnerabilities");


  script_tag(name:"summary", value:"This host is installed with WPN-XM Server
  Stack and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to
  - An error in WPN-XMs webinterface.
  - An improper validation of 'PHP.INI' file to change arbitrary 
    PHPs settings");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute client side code.

  Impact Level: Application");

  script_tag(name:"affected", value:"WPN-XM Serverstack for Windows Version 0.8.6");

  script_tag(name: "solution" , value:"No solution or patch is available as of
  10th February, 2017. Information regarding this issue will be updated once the
  solution details are available. For updates refer to http://www.wpn-xm.org/");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL" , value:"https://www.exploit-db.com/exploits/39678/");
  script_xref(name:"URL" , value:"http://seclists.org/bugtraq/2016/Apr/58");
  script_xref(name:"URL" , value:"http://seclists.org/bugtraq/2016/Apr/59");
  script_xref(name:"URL" , value:"http://seclists.org/bugtraq/2016/Apr/56");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wpn_xm_server_stack_detect.nasl");
  script_mandatory_keys("WPN-XM/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_keepalive.inc");
include("host_details.inc");
include("http_func.inc");

# Variable Initialization
url = "";
dir = "";
wpnport = "";

## Get HTTP Port
if(!wpnport = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Confluence Location
if(!dir = get_app_location(cpe:CPE, port:wpnport)){
  exit(0);
}

url = dir + 'tools/webinterface/index.php?page="/><script>alert(document.cookie)</script>';

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:wpnport, url:url, check_header:TRUE, 
                   pattern:"<script>alert\(document.cookie\)</script>",
                   extra_check:make_list(">Configuration<", ">phpmyadmin<")))
{
  report = report_vuln_url( port:wpnport, url:url );
  security_message(port:wpnport, data:report);
  exit(0);
}
