###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_live555_bof_vuln_15_lin.nasl 9421 2018-04-10 10:20:06Z asteins $
#
# LIVE555 Streaming Media Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:live5555:streaming_media";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107102");
  script_version("$Revision: 9421 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-10 12:20:06 +0200 (Tue, 10 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-05-22 12:42:40 +0200 (Mon, 22 May 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("LIVE555 Streaming Media Buffer Overflow Vulnerability (Linux)");

  script_tag(name: "summary", value:"The host is installed with LIVE555 Streaming Media and is prone to a buffer overflow vulnerability.");

  script_tag(name: "vuldetect", value:"Get the installed version with the help of the detection  NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value:"The flaw is due to a buffer overflow error in the parseRTSPRequestString function in RTSPServer.cpp file");

  script_tag(name: "impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Live555 Media Streaming Versions before 2015.07.23.");

  script_tag(name: "solution" , value:"Upgrade to 2015.07.23 or later versions. For updates refer to http://www.live555.com/");

  script_tag(name: "solution_type", value:"VendorFix");

  script_xref(name: "URL", value: "http://www.live555.com/liveMedia/public/changelog.txt");
  script_xref(name: "URL", value: "https://blogs.securiteam.com/index.php/archives/2543");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_live555_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("live555_streaming_media/ver", "Host/runs_unixoide");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)) exit(0);
if(!Ver = get_app_version(cpe:CPE, port:Port)) exit(0);

if(Ver =~ "^2015\."){
  if(version_is_less(version:Ver, test_version:"2015.07.23")){
    fix = "2015.07.23";
    VULN = TRUE;
  }
}

if(VULN){
  report = report_fixed_ver(installed_version:Ver, fixed_version:fix);
  security_message(port:Port, data:report);
  exit(0);
}

exit(99);
