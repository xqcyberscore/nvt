###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jasig_cas_mult_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Jasig Cas Server Multiple Cross Site Scripting Vulnerabilities
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

CPE = "cpe:/a:apereo:central_authentication_service";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806502");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-19 13:02:46 +0530 (Mon, 19 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Jasig Cas Server Multiple Cross Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Jasig Cas Server
  and is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - OpenID client does not validate input to the 'username' parameter while login
    before returning it to users.

  - OAuth server does not validate input to the 'redirect_uri' parameter before
    returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Jasig CAS server version 4.0.1");

  script_tag(name:"solution", value:"Upgrade to Jasig CAS server version 4.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Sep/88");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/536510");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jasig_cas_server_detect.nasl");
  script_mandatory_keys("Jasig CAS server/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.ja-sig.org/products/cas");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!casPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:casPort)){
  exit(0);
}

url = dir + '/openid/username"\nonmouseover="<script>alert(document.cookie);</script>';

if(http_vuln_check(port:casPort, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\);</script>"))
{
  report = report_vuln_url( port:casPort, url:url );
  security_message(port:casPort, data:report);
  exit(0);
}
