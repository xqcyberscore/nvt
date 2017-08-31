###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_piwik_php_code_exec_vuln.nasl 6704 2017-07-12 14:13:36Z cfischer $
#
# Piwik PHP Code Execution Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:piwik:piwik";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900992");
  script_version("$Revision: 6704 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 16:13:36 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4140");
  script_bugtraq_id(37314);
  script_name("Piwik PHP Code Execution Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37078");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/12/14/1");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0910-exploits/piwik-upload.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("sw_piwik_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwik/installed");

  script_tag(name : "impact" , value : "Successful exploitation will let the remote attackers execute malicious PHP
  code to compromise the remote machine running the vulnerable application.
  Impact Level: Application");
  script_tag(name : "affected" , value : "Open Flash Chart version 2 Beta 1 through 2.x
  Piwik version 0.2.35 through 0.4.3 on all platforms.");
  script_tag(name : "insight" , value : "This flaw is due to improper validatin of data passed into 'name' and
  'HTTP_RAW_POST_DATA' parameters in ofc_upload_image.php which can be exploited
  to create php files containing malicious php code.");
  script_tag(name : "solution" , value : "Upgrade Piwik to 0.4.4 or higher version,
  http://piwik.org/ and for Open Flash Chart,

  For Open Flash Chart, No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Piwik and is prone to PHP Code Execution
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(safe_checks()){
  exit(0);
}

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if (dir == "/") dir = "";

url = dir + "/libs/open-flash-chart/php-ofc-library" +
            "/ofc_upload_image.php?name=openvas.php";

request = http_get(item:url, port:port);
response = http_keepalive_send_recv(port:port, data:request);

if("openvas.php" >< response && "tmp-upload-images" >< response &&
    egrep(pattern:"^HTTP/.* 200 OK", string:response))
{
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);