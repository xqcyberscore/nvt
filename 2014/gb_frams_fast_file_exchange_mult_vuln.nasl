###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_frams_fast_file_exchange_mult_vuln.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# Frams&qt Fast File EXchange Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804664");
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-3876", "CVE-2014-3877", "CVE-2014-3875");
  script_bugtraq_id(67785, 67788, 67783);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-04 10:06:54 +0530 (Fri, 04 Jul 2014)");
  script_name("Frams&qt Fast File EXchange Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Frams&qt Fast File EXchange and is prone to
  multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is possible to
  read a given string.");
  script_tag(name:"insight", value:"Multiple flaws are due to,
  - An input passed via the 'akey' parameter to /rup is not properly sanitised before
  being returned to the user.
  - An input passed via the 'addto' parameter to /fup is not properly sanitised
  before being returned to the user.
  - An input passed via the 'disclaimer' and 'gm' parameters to /fuc is not properly
  sanitised before being returned to the user.
  - Application allows users to perform certain actions via HTTP requests without
  performing proper validity checks to verify the requests.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct HTTP response splitting,
  conduct request forgery attacks and execute arbitrary HTML and script code in a
  user's browser session in the context of an affected site.

  Impact Level: Application");
  script_tag(name:"affected", value:"Frams&qt Fast File EXchange before version 20140526");
  script_tag(name:"solution", value:"Upgrade to Frams&qt Fast File EXchange version 20140526 or later.
  For updates refer to http://fex.rus.uni-stuttgart.de");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58486");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q2/405");
  script_xref(name:"URL", value:"http://fex.rus.uni-stuttgart.de/fex.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126906");
  script_xref(name:"URL", value:"https://www.lsexperts.de/advisories/lse-2014-05-22.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("fexsrv/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
req = "";
res = "";
fexPort = "";

## Get HTTP Port
fexPort = get_http_port(default:8080);

## Get the banner and confirm application
banner = get_http_banner(port:fexPort);
if(!banner || "Server: fexsrv" >!< banner) exit(0);

## Construct the Attack Request
url = "/rup?akey=foo%22%20onmouseover=alert%28%22XSS-test%22%29%20bar=%22";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:fexPort, url:url, check_header:TRUE,
                   pattern:'onmouseover=alert.*XSS-test.*bar',
                   extra_check: make_list('F*EX operation control<', 'F*EX redirect<'))){
  report = report_vuln_url( port:fexPort, url:url );
  security_message(port:fexPort, data:report);
  exit(0);
}

exit(99);
