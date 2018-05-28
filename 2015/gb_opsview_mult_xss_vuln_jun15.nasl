###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opsview_mult_xss_vuln_jun15.nasl 9978 2018-05-28 08:52:24Z cfischer $
#
# Opsview Multiple Cross Site Scripting Vulnerabilities - June15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805663");
  script_version("$Revision: 9978 $");
  script_cve_id("CVE-2015-4420");
  script_bugtraq_id(75223);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 10:52:24 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2015-06-23 19:01:29 +0530 (Tue, 23 Jun 2015)");
  script_name("Opsview Multiple Cross Site Scripting Vulnerabilities - June15");

  script_tag(name:"summary", value:"This host is installed with Opsview and is
  prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to get vulnerable version or not.");

  script_tag(name: "insight" , value:"Multiple flaws exists due to,
  improper validation of user input to state/service /user/admin.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  to execute arbitrary code.

  Impact Level: Application");

  script_tag(name:"affected", value:"Opsview version 4.6.2 and earlier");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a
  newer release, disable respective features, remove the product or replace
  the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/37271/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

opPort = get_http_port(default:80);
dir = "/status/hostgroup";

sndReq = http_get(item:dir, port:opPort);
rcvRes = http_keepalive_send_recv(port:opPort, data:sndReq);

if("Opsview login page" >< rcvRes && 'class="float_right colorgrey30">OPSVIEW' >< rcvRes)
{
  Ver = eregmatch(pattern:"class='mid'>Opsview.*([0-9.]+)", string:rcvRes);
  if(Ver[0]){
    opVer = eregmatch(pattern:"([0-9.]+)", string:Ver[0]);
  }

  if(opVer[0])
  {
    if(version_is_less_equal(version:opVer[0], test_version:"4.6.2"))
    {
      report = 'Installed version: ' + opVer[0] + '\n' +
               'Fixed version:     ' + "NoneAvailable" + '\n';
      security_message(data:report, port:opPort);
      exit(0);
    }
  }
}
