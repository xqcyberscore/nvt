###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wpn_xm_server_stack_mult_vuln.nasl 7160 2017-09-18 07:39:22Z cfischer $
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
  script_version("$Revision: 7160 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 09:39:22 +0200 (Mon, 18 Sep 2017) $");
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

  script_tag(name: "solution" , value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.
");

  script_tag(name:"solution_type", value:"WillNotFix");

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

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

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
