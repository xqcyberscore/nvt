##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt56u_router_mult_vuln.nasl 30088 2013-06-11 14:55:27Z June$
#
# ASUS RT56U Router Multiple Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803715");
  script_version("$Revision: 6698 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:00:17 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-06-11 13:49:12 +0530 (Tue, 11 Jun 2013)");
  script_name("ASUS RT56U Router Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25998");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/asus-rt56u-remote-command-injection");
  script_xref(name : "URL" , value : "http://forelsec.blogspot.in/2013/06/asus-rt56u-remote-command-injection.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RT-N56U/banner");

  script_tag(name:"insight", value:"The flaws are due to insufficient (or rather, a complete lack
  thereof) input sensitization leads to the injection of shell commands. It is
  possible to upload and execute a backdoor.");
  script_tag(name:"solution", value:"No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running ASUS RT56U Router and is prone to multiple
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary shell commands and obtain the sensitive information.

  Impact Level: Application");
  script_tag(name:"affected", value:"Asus RT56U version 3.0.0.4.360 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);

## Confirm the device from banner
banner = get_http_banner(port: port);
if(banner && 'WWW-Authenticate: Basic realm="RT-N56U"' >!< banner){
  exit(0);
}

## Confirm the exploit by reading  content of Nologin.asp
if(http_vuln_check(port:port, url:"/Nologin.asp", pattern:">Login user IP:",
   extra_check:make_list(">You cannot Login unless logout another user first",
                         ">ASUS Wireless Router Web Manager<")))
{
  security_message(port:port);
  exit(0);
}

exit(99);
